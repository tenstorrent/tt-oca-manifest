// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Structural checks.
 */

#include "parser.h"

#include "oca_layout.h"
#include "oca_layout_classic.h"
#include "oca_layout_pqc.h"
#include "oca_variant.h"

oca_result_t oca_check_length(size_t actual_length)
{
    /* Minimum framing: the buffer must hold the smallest variant body so the
     * magic and every shared/Classic-range field can be read safely. Once the
     * magic selects a variant, oca_validate() additionally requires the full
     * per-variant body size (e.g., 36864 for PQC) before any high-offset PQC
     * field is read. */
    if (actual_length < OCA_CLASSIC_BODY_SIZE) {
        return OCA_FAIL_TRUNCATED;
    }
    return OCA_OK;
}

oca_result_t oca_check_magic(const uint8_t *body)
{
    oca_result_t status;
    (void)oca_variant_for_body(body, &status);
    return status;
}

oca_result_t oca_check_trailer(const uint8_t *body)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* The trailer that closes the signed region. */
    for (unsigned i = 0; i < v->trailer_len; ++i) {
        if (body[v->off_trailer + i] != v->trailer_byte) {
            return OCA_FAIL_TRAILER;
        }
    }
    /* Any variant-specific fixed-fill region (PQC's 0x35 classic-trailer
     * slot). A zero-length region (Classic) makes this a no-op. */
    for (unsigned i = 0; i < v->fill_len; ++i) {
        if (body[v->off_fill + i] != v->fill_byte) {
            return OCA_FAIL_TRAILER;
        }
    }
    return OCA_OK;
}

oca_result_t oca_check_format_version(const uint8_t *body)
{
    uint16_t manifest_major =
        oca_le_u16(body + OCA_OFF_MANIFEST_VERSION_MAJOR);
    if (manifest_major > OCA_LIB_MANIFEST_MAJOR) {
        return OCA_FAIL_FORMAT_VERSION_MISMATCH;
    }
    /* Older or equal major: accepted. Newer minor on the current major:
     * accepted (additive-only on the producer side). */
    return OCA_OK;
}

/* Pin the peek window and the public identifier width to the layout, so a moved
 * field fails the build rather than reading past the advertised window. C11 guard
 * matches oca_layout_pqc.h — the library builds -std=c99 -pedantic -Werror. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(OCA_MANIFEST_PEEK_MIN == OCA_OFF_MANIFEST_LENGTH + 4u,
               "peek window must end at manifest_length");
_Static_assert(OCA_OFF_MAGIC == 0u, "peek assumes the magic leads the body");
_Static_assert(OCA_MANIFEST_IDENTIFIER_LEN == OCA_LEN_MANIFEST_IDENTIFIER,
               "public identifier width must match the layout");
_Static_assert(OCA_OFF_MANIFEST_IDENTIFIER + OCA_LEN_MANIFEST_IDENTIFIER
                   <= OCA_MANIFEST_PEEK_MIN,
               "manifest_identifier must lie inside the peek window");
#endif

oca_result_t oca_peek_manifest(const uint8_t *head, size_t head_len,
                               oca_manifest_peek_t *out)
{
    if (head == 0 || out == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    /* Not oca_check_length(): its 4096 floor is the requirement for the body. */
    if (head_len < OCA_MANIFEST_PEEK_MIN) {
        return OCA_FAIL_TRUNCATED;
    }

    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(head, &status);
    if (v == 0) {
        return status;
    }

    out->body_size       = v->body_size;      /* from the magic, not the manifest */
    out->variant_name    = v->name;
    out->declared_length = oca_le_u32(head + OCA_OFF_MANIFEST_LENGTH);
    out->version_major   = oca_le_u16(head + OCA_OFF_MANIFEST_VERSION_MAJOR);
    out->version_minor   = oca_le_u16(head + OCA_OFF_MANIFEST_VERSION_MINOR);

    /* Sanitize to printable ASCII; no libc, so copy by hand. */
    const uint8_t *id = head + OCA_OFF_MANIFEST_IDENTIFIER;
    for (unsigned i = 0u; i < OCA_MANIFEST_IDENTIFIER_LEN; ++i) {
        out->identifier[i] =
            (id[i] >= 0x20u && id[i] <= 0x7Eu) ? (char)id[i] : '?';
    }
    /* Trim trailing padding from the SOURCE bytes — NULs became '?' above. */
    unsigned len = OCA_MANIFEST_IDENTIFIER_LEN;
    while (len > 0u && (id[len - 1u] == 0x00u || id[len - 1u] == 0x20u)) {
        len--;
    }
    for (unsigned i = len; i <= OCA_MANIFEST_IDENTIFIER_LEN; ++i) {
        out->identifier[i] = '\0';
    }
    return OCA_OK;
}

oca_result_t oca_check_manifest_length(const uint8_t *body)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* manifest_length is a u32; a body size never approaches 2^32, so the
     * comparison is exact in either direction. */
    uint32_t declared = oca_le_u32(body + OCA_OFF_MANIFEST_LENGTH);
    if ((size_t)declared != v->body_size) {
        return OCA_FAIL_MANIFEST_LENGTH;
    }
    return OCA_OK;
}

oca_result_t oca_check_reserved_bits(const uint8_t *body)
{
    /* Reserved bit-ranges inside operative fields — selector_bits[127:105],
     * lifecycle_<level>_states[31:7], and demotion_control[15:4] — are the
     * Producer's responsibility to zero (each is documented "shall be 0" in the
     * field tables). The Consumer, however, does not reject a manifest merely
     * because such a reserved bit is set:
     *
     *   - boot-manifest v2 requires the Consumer to "not process, depend on,
     *     infer, or act upon any reserved field" and does not oblige it to
     *     verify reserved regions hold 0x00;
     *   - reserved regions are explicitly "available for backward-compatible
     *     minor-version extension," and this library accepts a newer minor on
     *     the same major (additive-only) — so rejecting a set reserved bit
     *     would break forward compatibility with a future minor that defines it.
     *
     * The operative decoders (oca_selector_decode, oca_lifecycle_check) already
     * mask to the currently-defined bits, so reserved bits are ignored rather
     * than rejected. This stage is retained as a documented no-op to keep the
     * composable-check API and the canonical validation order stable. */
    (void)body;
    return OCA_OK;
}

oca_result_t oca_check_secure_boot_invariant(const uint8_t *body)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    uint8_t secure_boot_control = body[OCA_OFF_SECURE_BOOT_CONTROL];
    /* secure_boot_pqc names a PQC signature this variant has no fields to
     * carry — a format violation "regardless of secure-boot state", so it is
     * checked before the enable bit is even consulted. Data-driven via the
     * descriptor: a variant with no PQC crypto has len_pqc_signature == 0. */
    if ((secure_boot_control & OCA_SECURE_BOOT_PQC_BIT) != 0u
        && v->len_pqc_signature == 0u) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }
    bool secure_boot_enabled =
        (secure_boot_control & OCA_SECURE_BOOT_ENFORCED_BIT) != 0u;
    if (secure_boot_enabled) {
        return OCA_OK; /* signing fields are allowed to be non-zero. */
    }
    /* secure_boot == 0: signature_classic, public_key_classic, and
     * public_key_select_classic must be all zero (the packer enforces this
     * on the producer side; we verify on the consumer side). The
     * classic-crypto key fields are shared offsets; signature_classic sits at
     * the variant's signature offset. */
    for (unsigned i = 0; i < OCA_LEN_SIGNATURE; ++i) {
        if (body[v->off_signature + i] != 0u) {
            return OCA_FAIL_SECURE_BOOT_INVARIANT;
        }
    }
    for (unsigned i = 0; i < OCA_LEN_PUBLIC_KEY; ++i) {
        if (body[OCA_OFF_PUBLIC_KEY + i] != 0u) {
            return OCA_FAIL_SECURE_BOOT_INVARIANT;
        }
    }
    for (unsigned i = 0; i < OCA_LEN_PUBLIC_KEY_SELECT; ++i) {
        if (body[OCA_OFF_PUBLIC_KEY_SELECT + i] != 0u) {
            return OCA_FAIL_SECURE_BOOT_INVARIANT;
        }
    }
    if (body[OCA_OFF_SIGNATURE_TYPE] != 0u
        || body[OCA_OFF_SIGNATURE_ENCODING] != 0u
        || body[OCA_OFF_PUBLIC_KEY_ENCODING] != 0u) {
        return OCA_FAIL_SECURE_BOOT_INVARIANT;
    }
    return OCA_OK;
}

/* Encoded lengths from the format's classic encoded-length table. Raw lengths
 * are fixed by the algorithm; a DER ECDSA signature is variable-length, so its
 * size field carries the algorithm MAXIMUM instead of an exact count. */

/** Raw RSA-3072 public key: big-endian modulus (384) || big-endian exponent (4). */
#define RAW_RSA_3072_PUBLIC_KEY_BYTES  388u
/** Raw RSA-3072 signature: the big-endian signature integer. */
#define RAW_RSA_3072_SIGNATURE_BYTES   384u
/** Raw ECDSA P-256 public key: SEC1 uncompressed point, 0x04 || X || Y. */
#define RAW_EC_P256_PUBLIC_KEY_BYTES    65u
/** Raw ECDSA P-256 signature: r || s, each 32 bytes big-endian. */
#define RAW_EC_P256_SIGNATURE_BYTES     64u
/** Largest RFC 3279 ECDSA-Sig-Value a P-256 key can produce. */
#define DER_EC_P256_SIGNATURE_MAX_BYTES 72u

oca_result_t oca_check_crypto_field_sizes(const uint8_t *body)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* Keyed on the manifest's own secure_boot bits, exactly as
     * oca_check_secure_boot_invariant is, and for the same reason: this is a
     * producer-side property of these bytes. The two together partition the
     * question completely — a manifest declaring itself non-secure must zero its
     * signing fields (that check), and one declaring itself secure must describe
     * them consistently (this one). Neither asks what the device resolved to.
     *
     * Each class's description is validated only when its class bit names it:
     * a PQC-only manifest zeroes the classical fields, and the classical rules
     * must not fire on fields the manifest never uses. */
    uint8_t control = body[OCA_OFF_SECURE_BOOT_CONTROL];
    if ((control & OCA_SECURE_BOOT_ENFORCED_BIT) == 0u) {
        return OCA_OK;
    }

    if ((control & OCA_SECURE_BOOT_CLASSIC_BIT) != 0u) {
        uint16_t sig_size = oca_le_u16(body + OCA_OFF_SIGNATURE_SIZE);
        uint16_t key_size = oca_le_u16(body + OCA_OFF_PUBLIC_KEY_SIZE);
        oca_encoding_t sig_enc = (oca_encoding_t)body[OCA_OFF_SIGNATURE_ENCODING];
        oca_encoding_t key_enc = (oca_encoding_t)body[OCA_OFF_PUBLIC_KEY_ENCODING];
        oca_primitive_type_t prim =
            (oca_primitive_type_t)body[OCA_OFF_SIGNATURE_TYPE];

        if (sig_size == 0u || sig_size > OCA_LEN_SIGNATURE
            || key_size == 0u || key_size > OCA_LEN_PUBLIC_KEY) {
            return OCA_FAIL_CRYPTO_FIELD_SIZE;
        }

        uint16_t want_sig;
        uint16_t want_key;
        if (prim == OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256) {
            /* DER is not defined for an RSA signature. */
            if (sig_enc != OCA_ENCODING_RAW) {
                return OCA_FAIL_CRYPTO_FIELD_SIZE;
            }
            want_sig = RAW_RSA_3072_SIGNATURE_BYTES;
            /* A DER RSA key is PKCS#1, whose length varies with the public
             * exponent, so only the field bound above constrains it. */
            want_key = (key_enc == OCA_ENCODING_RAW)
                           ? RAW_RSA_3072_PUBLIC_KEY_BYTES
                           : key_size;
        } else if (prim == OCA_PRIMITIVE_ECDSA_P256_SHA256) {
            want_sig = (sig_enc == OCA_ENCODING_DER)
                           ? DER_EC_P256_SIGNATURE_MAX_BYTES
                           : RAW_EC_P256_SIGNATURE_BYTES;
            /* DER is not defined for an EC public key. */
            if (key_enc != OCA_ENCODING_RAW) {
                return OCA_FAIL_CRYPTO_FIELD_SIZE;
            }
            want_key = RAW_EC_P256_PUBLIC_KEY_BYTES;
        } else {
            return OCA_FAIL_CRYPTO_FIELD_SIZE;
        }

        if (sig_size != want_sig || key_size != want_key) {
            return OCA_FAIL_CRYPTO_FIELD_SIZE;
        }
    }

    /* PQC sizes: bounds only, for now. Each size field caps how far a later
     * parse reads into its companion field, so zero and beyond-the-field are
     * rejected here; per-algorithm exact sizes (ML-DSA / SLH-DSA) are pinned
     * when a PQC verification backend exists to consume them. The variant
     * gate mirrors the invariant's: a class bit naming a region the variant
     * does not carry is that check's rejection, not this one's. */
    if ((control & OCA_SECURE_BOOT_PQC_BIT) != 0u && v->len_pqc_signature != 0u) {
        uint16_t pqc_sig_size = oca_le_u16(body + OCA_PQC_OFF_SIGNATURE_SIZE);
        uint16_t pqc_key_size = oca_le_u16(body + OCA_PQC_OFF_PUBLIC_KEY_SIZE);
        if (pqc_sig_size == 0u
            || (size_t)pqc_sig_size > (size_t)OCA_PQC_LEN_SIGNATURE_PQC
            || pqc_key_size == 0u
            || (size_t)pqc_key_size > (size_t)OCA_PQC_LEN_PUBLIC_KEY) {
            return OCA_FAIL_CRYPTO_FIELD_SIZE;
        }
    }
    return OCA_OK;
}

oca_result_t oca_check_signature_class_group_codes(const uint8_t *body)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    const uint8_t *field = body + OCA_OFF_SIGNATURE_CLASS_REVOKE;
    uint8_t classic = field[OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE];
    uint8_t pqc     = field[OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE];

    /* Compared as whole bytes against the constants. Testing individual bits
     * within a group code would be wrong: a partially set code is not a partial
     * revocation and carries no meaning on its own. */
    if ((classic != 0u && classic != OCA_CLASS_REVOKE_CLASSIC_GROUP_CODE)
        || (pqc != 0u && pqc != OCA_CLASS_REVOKE_PQC_GROUP_CODE)) {
        return OCA_FAIL_GROUP_CODE;
    }
    return OCA_OK;
}

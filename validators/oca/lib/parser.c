// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Structural checks.
 */

#include "parser.h"

#include "algorithms.h"
#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_layout_classic.h"
#include "oca_layout_pqc.h"
#include "oca_variant.h"
#include "secure_boot.h"

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

oca_result_t oca_check_signature_class_variant(const uint8_t *body)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* secure_boot_pqc names a PQC signature this variant has no fields to
     * carry — a format violation regardless of secure-boot state. Data-driven
     * via the descriptor: a variant with no PQC crypto has
     * len_pqc_signature == 0.
     *
     * The signing fields themselves are not judged here. They are
     * Secure-Boot-only, so a Consumer ignores them while secure boot is
     * disabled and validates them, through oca_check_signing_description(), once
     * the determination puts secure boot in force. */
    if ((body[OCA_OFF_SECURE_BOOT_CONTROL] & OCA_SECURE_BOOT_PQC_BIT) != 0u
        && v->len_pqc_signature == 0u) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }
    return OCA_OK;
}

/**
 * @brief Whether a key or signature field holds anything past its valid bytes.
 *
 * The bytes after a value's declared size are padding. They are refused unless
 * zero: a signature field lies outside the signed region, so any other content
 * there would make byte-distinct bundles of one signed manifest.
 *
 * @param[in] field       Start of the field.
 * @param[in] field_len   Width of the field.
 * @param[in] valid_len   The field's declared size, already held to
 *                        @p field_len.
 * @return Non-zero when any byte in [valid_len, field_len) is non-zero.
 */
static int padding_is_dirty(const uint8_t *field, size_t field_len, size_t valid_len)
{
    return oca_ct_any_nonzero(field + valid_len, field_len - valid_len);
}

/**
 * @brief The size a key or signature must declare in its stated encoding.
 *
 * Every encoding is matched against the ones its algorithm defines, so an
 * unset, reserved or integrator value never falls through to another
 * encoding's size rule.
 *
 * @param[in]  encoding  The value's *_encoding_* byte.
 * @param[in]  raw       The algorithm's raw length for this value.
 * @param[in]  der       Whether the algorithm accepts DER for this value.
 * @param[in]  der_size  The size a DER encoding must declare.
 * @param[out] want      Receives the required size on OCA_OK.
 * @retval OCA_OK                          @p want holds the required size.
 * @retval OCA_FAIL_ALGORITHM_NOT_ENABLED  DER, which the build configuration
 *                                         turns off for this algorithm.
 * @retval OCA_FAIL_CRYPTO_FIELD_SIZE      DER where the format defines none
 *                                         for this algorithm, or an encoding
 *                                         that is neither raw nor DER.
 */
static oca_result_t required_size(uint8_t encoding, uint16_t raw,
                                  oca_der_support_t der, uint16_t der_size,
                                  uint16_t *want)
{
    if (encoding == (uint8_t)OCA_ENCODING_RAW) {
        *want = raw;
        return OCA_OK;
    }
    if (encoding != (uint8_t)OCA_ENCODING_DER || der == OCA_DER_UNDEFINED) {
        return OCA_FAIL_CRYPTO_FIELD_SIZE;
    }
    /* Anything but an intact ENABLED is refused, so a corrupted value fails
     * closed. */
    if (der != OCA_DER_ENABLED) {
        return OCA_FAIL_ALGORITHM_NOT_ENABLED;
    }
    *want = der_size;
    return OCA_OK;
}

/** @brief Where one signature class keeps its signing description. */
typedef struct class_description {
    oca_key_algorithm_t family;      /**< Which class's algorithm table applies. */
    size_t off_type;                 /**< signature_type_* */
    size_t off_signature_encoding;   /**< signature_encoding_* */
    size_t off_public_key_encoding;  /**< public_key_encoding_* */
    size_t off_signature_size;       /**< signature_size_* */
    size_t off_public_key_size;      /**< public_key_size_* */
    size_t off_signature;            /**< The signature field. */
    size_t len_signature;            /**< Its width. */
    size_t off_public_key;           /**< The public key field. */
    size_t len_public_key;           /**< Its width. */
} class_description_t;

/**
 * @brief Validate one enforced class's signing description.
 *
 * The algorithm is resolved first, so a manifest naming one this build does
 * not enable, or a reserved value, is reported as that rather than as a size
 * that happens not to fit.
 *
 * @param[in] body  Whole variant body.
 * @param[in] d     Where the class's fields are.
 * @retval OCA_OK                          The description is consistent.
 * @retval OCA_FAIL_ALGORITHM_NOT_ENABLED  The algorithm, or a DER encoding it
 *                                         uses, is not enabled in this build.
 * @retval OCA_FAIL_ALGORITHM_RESERVED     The signature_type is reserved.
 * @retval OCA_FAIL_CRYPTO_FIELD_SIZE      A size or encoding does not fit the
 *                                         algorithm, or padding is not zero.
 * @return The first failing step's result, always one of the codes above.
 */
static oca_result_t check_class_description(const uint8_t *body,
                                             const class_description_t *d)
{
    oca_result_t status;
    const oca_signature_algorithm_t *algorithm =
        oca_signature_algorithm(d->family, body[d->off_type], &status);
    if (algorithm == 0) {
        return status;
    }

    uint16_t sig_size = oca_le_u16(body + d->off_signature_size);
    uint16_t key_size = oca_le_u16(body + d->off_public_key_size);
    if (sig_size == 0u || sig_size > d->len_signature
        || key_size == 0u || key_size > d->len_public_key) {
        return OCA_FAIL_CRYPTO_FIELD_SIZE;
    }

    /* A DER public key is PKCS#1, whose length varies with the public
     * exponent, so its declared size is taken as exact; the field bound above
     * is all that constrains it. A DER signature declares the algorithm's
     * maximum DER length. */
    uint16_t want_sig;
    uint16_t want_key;
    status = required_size(body[d->off_signature_encoding],
                           algorithm->signature_raw, algorithm->signature_der,
                           algorithm->signature_der_max, &want_sig);
    if (status != OCA_OK) {
        return status;
    }
    status = required_size(body[d->off_public_key_encoding],
                           algorithm->public_key_raw, algorithm->public_key_der,
                           key_size, &want_key);
    if (status != OCA_OK) {
        return status;
    }
    if (sig_size != want_sig || key_size != want_key) {
        return OCA_FAIL_CRYPTO_FIELD_SIZE;
    }

    /* Confirm the signature and public key are zero-padded past their declared
     * sizes. */
    if (padding_is_dirty(body + d->off_signature, d->len_signature, sig_size)
        || padding_is_dirty(body + d->off_public_key, d->len_public_key,
                            key_size)) {
        return OCA_FAIL_CRYPTO_FIELD_SIZE;
    }
    return OCA_OK;
}

oca_result_t oca_check_signing_description(const uint8_t *body,
                                          const oca_callbacks_t *cb,
                                          const oca_validation_context_t *ctx)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* The signing description is Secure-Boot-only: validated when secure boot
     * is in force and ignored otherwise. In force is the determination's
     * answer, not the manifest's own enforced bit, because a part that enforces
     * secure boot itself uses these fields whatever that bit says. */
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }
    /* Each class's description is validated only when that class is enforced:
     * a PQC-only manifest zeroes the classical fields, and the classical rules
     * must not fire on fields the manifest never uses. */
    oca_result_t classes = oca_secure_boot_confirm_classes(body, ctx);
    if (classes != OCA_OK) {
        return classes;
    }

    /* Skipped only on an exact OCA_SECURE_FALSE, so a corrupted
     * enforcement word runs a class's check rather than skipping it. */
    if (ctx->secure_boot_enforce_classic != OCA_SECURE_FALSE) {
        /* signature_classic is the one variant-positioned field here, so its
         * offset comes from the descriptor. */
        const class_description_t classical = {
            .family                  = OCA_KEY_ALGO_CLASSIC,
            .off_type                = OCA_OFF_SIGNATURE_TYPE,
            .off_signature_encoding  = OCA_OFF_SIGNATURE_ENCODING,
            .off_public_key_encoding = OCA_OFF_PUBLIC_KEY_ENCODING,
            .off_signature_size      = OCA_OFF_SIGNATURE_SIZE,
            .off_public_key_size     = OCA_OFF_PUBLIC_KEY_SIZE,
            .off_signature           = v->off_signature,
            .len_signature           = OCA_LEN_SIGNATURE,
            .off_public_key          = OCA_OFF_PUBLIC_KEY,
            .len_public_key          = OCA_LEN_PUBLIC_KEY,
        };
        status = check_class_description(body, &classical);
        if (status != OCA_OK) {
            return status;
        }
    }

    if (ctx->secure_boot_enforce_pqc != OCA_SECURE_FALSE) {
        /* Never read PQC offsets out of a body that has none. The confirm
         * above already refused this; it is repeated at the point of use. */
        if (ctx->manifest_is_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
        }
        const class_description_t pqc = {
            .family                  = OCA_KEY_ALGO_PQC,
            .off_type                = OCA_PQC_OFF_SIGNATURE_TYPE,
            .off_signature_encoding  = OCA_PQC_OFF_SIGNATURE_ENCODING,
            .off_public_key_encoding = OCA_PQC_OFF_PUBLIC_KEY_ENCODING,
            .off_signature_size      = OCA_PQC_OFF_SIGNATURE_SIZE,
            .off_public_key_size     = OCA_PQC_OFF_PUBLIC_KEY_SIZE,
            .off_signature           = OCA_PQC_OFF_SIGNATURE_PQC,
            .len_signature           = OCA_PQC_LEN_SIGNATURE_PQC,
            .off_public_key          = OCA_PQC_OFF_PUBLIC_KEY,
            .len_public_key          = OCA_PQC_LEN_PUBLIC_KEY,
        };
        status = check_class_description(body, &pqc);
        if (status != OCA_OK) {
            return status;
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

    /* Every defined class of a group set while its code byte is 0x00 disables
     * the group without the code, which only the intact code may do. */
    uint8_t classic_classes = field[OCA_CLASS_REVOKE_OFF_CLASSIC_CLASSES];
    uint8_t pqc_classes     = field[OCA_CLASS_REVOKE_OFF_PQC_CLASSES];
    if ((classic == 0u
         && (classic_classes & OCA_CLASS_REVOKE_CLASSIC_DEFINED_CLASSES)
            == OCA_CLASS_REVOKE_CLASSIC_DEFINED_CLASSES)
        || (pqc == 0u
            && (pqc_classes & OCA_CLASS_REVOKE_PQC_DEFINED_CLASSES)
               == OCA_CLASS_REVOKE_PQC_DEFINED_CLASSES)) {
        return OCA_FAIL_GROUP_CODE;
    }
    return OCA_OK;
}

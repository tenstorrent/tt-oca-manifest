// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/*
 * cli_hwid.c — Hardware-identity callbacks backed by CLI flags.
 *
 * Every callback reads the options bound by cli_hwid_bind() and returns
 * OCA_HW_UNAVAILABLE when the relevant flag was not supplied — the "I don't
 * know" sentinel the validator turns into a hard fail.
 *
 * The options live at file scope rather than arriving through the callback,
 * because on a real part these values come from fuses or an ID register block
 * that the implementation reaches directly. A host tool substituting flags for
 * silicon should reach them the same way.
 */

#include "cli_hwid.h"

#include "openssl_crypto.h"

#include <string.h>

static const cli_options_t *g_opt;

void cli_hwid_bind(const cli_options_t *opt)
{
    g_opt = opt;
}

oca_hw_result_t cli_get_identity_bytes(oca_id_kind_t field,
                                       uint8_t out[32])
{
    if (g_opt == NULL) return OCA_HW_UNAVAILABLE;
    switch (field) {
        case OCA_ID_CHIPLET:
            if (!g_opt->chiplet_id_present) return OCA_HW_UNAVAILABLE;
            memcpy(out, g_opt->chiplet_id, 32);
            return OCA_HW_OK;
        case OCA_ID_PACKAGE:
            if (!g_opt->package_id_present) return OCA_HW_UNAVAILABLE;
            memcpy(out, g_opt->package_id, 32);
            return OCA_HW_OK;
        case OCA_ID_SYSTEM:
            if (!g_opt->system_id_present) return OCA_HW_UNAVAILABLE;
            memcpy(out, g_opt->system_id, 32);
            return OCA_HW_OK;
    }
    return OCA_HW_ERROR;
}

oca_hw_result_t cli_get_lifecycle_state(oca_lifecycle_level_t level,
                                        oca_lifecycle_token_t *out_state)
{
    (void)level;
    if (g_opt == NULL || !g_opt->lifecycle_present) {
        *out_state = OCA_LIFECYCLE_UNKNOWN;
        return OCA_HW_UNAVAILABLE;
    }
    *out_state = g_opt->lifecycle_token;
    return OCA_HW_OK;
}

oca_hw_result_t cli_get_version(oca_version_level_t level,
                                uint16_t *out_major,
                                uint16_t *out_minor)
{
    if (g_opt == NULL) return OCA_HW_UNAVAILABLE;
    switch (level) {
        case OCA_VERSION_LEVEL_CHIPLET:
            if (!g_opt->version_chiplet_present) return OCA_HW_UNAVAILABLE;
            *out_major = g_opt->version_chiplet_major;
            *out_minor = g_opt->version_chiplet_minor;
            return OCA_HW_OK;
        case OCA_VERSION_LEVEL_PACKAGE:
            if (!g_opt->version_package_present) return OCA_HW_UNAVAILABLE;
            *out_major = g_opt->version_package_major;
            *out_minor = g_opt->version_package_minor;
            return OCA_HW_OK;
        case OCA_VERSION_LEVEL_SYSTEM:
            if (!g_opt->version_system_present) return OCA_HW_UNAVAILABLE;
            *out_major = g_opt->version_system_major;
            *out_minor = g_opt->version_system_minor;
            return OCA_HW_OK;
    }
    return OCA_HW_ERROR;
}

/* Whether `public_key` is a raw key of `primitive`, selected in `select` at
 * the anchor's `slot`, whose whole encoding hashes to `anchor`, compared in
 * constant time.
 *
 * Both bindings matter. The digest covers the blob's validated length, every
 * byte the verifier uses: for a raw RSA key the exponent as well as the
 * modulus. And the anchor vouches only for its own slot: revocation is decided
 * from the select bitmap, so an anchor that ignored it would let a revoked key
 * claim another slot. Any other shape is unauthorized. */
static oca_result_t key_matches_anchor(const oca_crypto_blob_t *public_key,
                                       const uint8_t select[16], unsigned slot,
                                       oca_primitive_type_t primitive,
                                       const uint8_t anchor[32])
{
    if (public_key->encoding != OCA_ENCODING_RAW
        || public_key->primitive_type != primitive
        || public_key->length == 0u
        || public_key->length > public_key->field_length
        || ((select[slot / 8u] >> (slot % 8u)) & 1u) == 0u) {
        return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
    }

    uint8_t digest[32];
    if (openssl_sha256(public_key->bytes, public_key->length, digest) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    unsigned diff = 0u;
    for (unsigned i = 0u; i < 32u; ++i) {
        diff |= (unsigned)(digest[i] ^ anchor[i]);
    }
    return (diff == 0u) ? OCA_OK : OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
}

/* Root-key trust anchors.
 *
 * A host tool has no silicon anchor, so this stands in for one per algorithm
 * family: an explicit digest to match, or --trust-any-root-key for the cases
 * where the key is not what is under test. There is deliberately no default --
 * an unflagged run fails closed, exactly as an unwired callback would on a real
 * part, so a fixture sweep cannot quietly stop checking authorization. A
 * family's key is checked against that family's anchor only.
 */
oca_result_t cli_is_key_authorized(const oca_crypto_blob_t *public_key,
                                   const uint8_t select[16])
{
    if (g_opt == NULL) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    if (g_opt->trust_any_root_key) {
        return OCA_OK;
    }
    if (public_key == NULL || public_key->bytes == NULL || select == NULL) {
        return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
    }
    if (public_key->key_algorithm == OCA_KEY_ALGO_PQC) {
        if (!g_opt->root_key_digest_pqc_present) {
            return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
        }
        return key_matches_anchor(public_key, select, g_opt->root_key_slot_pqc,
                                  OCA_PRIMITIVE_ML_DSA_87, g_opt->root_key_digest_pqc);
    }
    if (!g_opt->root_key_digest_present) {
        return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
    }
    return key_matches_anchor(public_key, select, g_opt->root_key_slot,
                              OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256,
                              g_opt->root_key_digest);
}

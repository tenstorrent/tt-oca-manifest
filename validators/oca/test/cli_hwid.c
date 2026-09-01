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

/* Root-key trust anchor.
 *
 * A host tool has no silicon anchor, so this stands in for one: either an
 * explicit digest to match, or --trust-any-root-key for the cases where the key
 * is not what is under test. There is deliberately no default -- an unflagged
 * run fails closed, exactly as an unwired callback would on a real part, so a
 * fixture sweep cannot quietly stop checking authorization.
 */
oca_result_t cli_is_key_authorized(const oca_crypto_blob_t *public_key,
                                   const uint8_t select[16])
{
    (void)select;

    if (g_opt == NULL) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    if (g_opt->trust_any_root_key) {
        return OCA_OK;
    }
    if (!g_opt->root_key_digest_present) {
        return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
    }
    if (public_key == NULL || public_key->bytes == NULL
        || public_key->encoding != OCA_ENCODING_RAW
        || public_key->primitive_type != OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256) {
        /* Only a raw RSA-3072 key has a 384-byte modulus to digest; anything
         * else cannot be matched against this anchor shape. */
        return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
    }

    uint8_t digest[32];
    if (openssl_sha256(public_key->bytes, 384u, digest) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    unsigned diff = 0u;
    for (unsigned i = 0u; i < 32u; ++i) {
        diff |= (unsigned)(digest[i] ^ g_opt->root_key_digest[i]);
    }
    return (diff == 0u) ? OCA_OK : OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
}

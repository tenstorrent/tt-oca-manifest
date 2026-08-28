/**
 * @file
 * @brief Implementations of the unavailable-stub callbacks.
 */

#include "default_callbacks.h"

oca_result_t oca_default_sha256(const uint8_t *msg, size_t msg_len,
                                uint8_t out_digest[32])
{
    (void)msg;
    (void)msg_len;
    (void)out_digest;
    return OCA_FAIL_CALLBACK_UNAVAILABLE;
}

oca_result_t oca_default_verify_signature(
    const oca_crypto_blob_t *signature,
    const oca_crypto_blob_t *public_key,
    const uint8_t *signed_region, size_t signed_region_len)
{
    (void)signature;
    (void)public_key;
    (void)signed_region;
    (void)signed_region_len;
    return OCA_FAIL_CALLBACK_UNAVAILABLE;
}

oca_hw_result_t oca_default_get_identity_bytes(
    oca_id_kind_t field, uint8_t out[32])
{
    (void)field;
    (void)out;
    return OCA_HW_UNAVAILABLE;
}

oca_hw_result_t oca_default_get_lifecycle_state(
    oca_lifecycle_level_t level,
    oca_lifecycle_token_t *out_state)
{
    (void)level;
    if (out_state != 0) {
        *out_state = OCA_LIFECYCLE_UNKNOWN;
    }
    return OCA_HW_UNAVAILABLE;
}

oca_hw_result_t oca_default_get_version(
    oca_version_level_t level,
    uint16_t *out_major, uint16_t *out_minor)
{
    (void)level;
    if (out_major != 0) {
        *out_major = 0;
    }
    if (out_minor != 0) {
        *out_minor = 0;
    }
    return OCA_HW_UNAVAILABLE;
}

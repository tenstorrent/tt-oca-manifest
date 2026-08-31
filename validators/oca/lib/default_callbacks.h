// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Internal stubs used when the caller-supplied callback table has NULL
 * function pointers.
 *
 * Each stub returns the documented "unavailable" sentinel so that any
 * required callback that the caller hasn't wired produces a clean
 * OCA_FAIL_CALLBACK_UNAVAILABLE rather than crashing or silently passing.
 *
 * Not part of the public API. Library-private.
 */

#ifndef OCA_DEFAULT_CALLBACKS_H
#define OCA_DEFAULT_CALLBACKS_H

#include "oca_validator.h"

/**
 * @brief Unavailable-sentinel stub standing in for an unwired sha256 callback.
 *
 * Computes nothing and leaves @p out_digest untouched. Substituting this for a
 * NULL pointer is what turns an unwired callback into a clean refusal at the
 * point of use rather than a null dereference.
 *
 * @param[in]  msg         Ignored.
 * @param[in]  msg_len     Ignored.
 * @param[out] out_digest  Left untouched.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE  Always.
 */
oca_result_t       oca_default_sha256(
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out_digest[32]);

/**
 * @brief Unavailable-sentinel stub for an unwired verify_signature callback.
 *
 * Verifies nothing and never reports success, so an integration that forgot to
 * wire signature verification fails closed instead of booting unverified.
 *
 * @param[in] signature          Ignored.
 * @param[in] public_key         Ignored.
 * @param[in] signed_region      Ignored.
 * @param[in] signed_region_len  Ignored.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE  Always.
 */
oca_result_t       oca_default_verify_signature(
                       const oca_crypto_blob_t *signature,
                       const oca_crypto_blob_t *public_key,
                       const uint8_t *signed_region, size_t signed_region_len);

/**
 * @brief Unavailable-sentinel stub for an unwired get_identity_bytes callback.
 *
 * Reports unavailable, which the library treats as a hard failure — an identity
 * constraint is never waived because nothing was wired to answer it.
 *
 * @param[in]  field     Ignored.
 * @param[out] out       Left untouched.
 * @retval OCA_HW_UNAVAILABLE  Always.
 */
oca_hw_result_t  oca_default_get_identity_bytes(
                       oca_id_kind_t field,
                       uint8_t out[32]);

/**
 * @brief Unavailable-sentinel stub for an unwired get_lifecycle_state callback.
 *
 * Same fail-closed contract as oca_default_get_identity_bytes().
 *
 * @param[in]  level      Ignored.
 * @param[out] out_state  Left untouched.
 * @retval OCA_HW_UNAVAILABLE  Always.
 */
oca_hw_result_t  oca_default_get_lifecycle_state(
                       oca_lifecycle_level_t level,
                       oca_lifecycle_token_t *out_state);

/**
 * @brief Unavailable-sentinel stub for an unwired get_version callback.
 *
 * Same fail-closed contract as oca_default_get_identity_bytes().
 *
 * @param[in]  level      Ignored.
 * @param[out] out_major  Left untouched.
 * @param[out] out_minor  Left untouched.
 * @retval OCA_HW_UNAVAILABLE  Always.
 */
oca_hw_result_t  oca_default_get_version(
                       oca_version_level_t level,
                       uint16_t *out_major, uint16_t *out_minor);

#endif /* OCA_DEFAULT_CALLBACKS_H */

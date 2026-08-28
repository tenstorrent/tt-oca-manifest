/**
 * @file
 * @brief manifest_hash + signature_classic validation through caller-supplied
 * crypto callbacks.
 */

#ifndef OCA_CRYPTO_DISPATCH_H
#define OCA_CRYPTO_DISPATCH_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Recompute and compare the manifest's integrity digest.
 *
 * Backs oca_check_manifest_hash(). Detects corruption only — the expected
 * digest lives in the manifest's unsigned tail, so it is not a trust boundary.
 * See oca_validator.h for that distinction.
 *
 * @param[in] body  Whole variant body.
 * @param[in] cb    Callback table; cb->sha256 is required.
 * @retval OCA_OK                          Recomputed digest matches.
 * @retval OCA_FAIL_MANIFEST_HASH          Digest mismatch.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   cb->sha256 missing or unavailable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_manifest_hash_check(const uint8_t *body,
                                     const oca_callbacks_t *cb);

/**
 * @brief Verify every enforced manifest signature through the caller's crypto
 *        callback.
 *
 * Backs oca_check_signature(). For each signature class the manifest enforces
 * — classical, PQC, or both — assembles that class's signature and public-key
 * blobs with their encodings and algorithm family, bounds the signed region,
 * and delegates the cryptography; the library performs none itself. A hybrid
 * manifest is a logical AND: either class failing fails the manifest.
 *
 * @param[in]  body  Whole variant body.
 * @param[in]  cb    Callback table; cb->verify_signature is required under
 *                   secure boot and invoked once per enforced class.
 * @param[out] ctx   Read for the recorded enforcement and the per-class
 *                   authorizations; written, on success, with the
 *                   authentication itself — set only after EVERY enforced
 *                   class's callback returned OCA_OK. NULL is refused by the
 *                   secure-boot confirmation.
 * @retval OCA_OK                          Every enforced class verified, or
 *                                         secure boot not in force.
 * @retval OCA_FAIL_SIGNATURE              A verification failed.
 * @retval OCA_FAIL_ROOT_KEY_UNAUTHORIZED  An enforced class's key was never
 *                                         vouched for by its anchor.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL  No class enforced in an engaged
 *                                         context, or PQC enforced on a
 *                                         variant with no PQC fields.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Verify callback missing under secure boot.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED  The live determination — or the
 *                                         recorded enforcement — no longer
 *                                         matches the manifest.
 * @return Otherwise the magic or variant failure from resolving @p body, or
 *         the secure-boot confirmation's failure.
 */
oca_result_t oca_signature_check(const uint8_t *body,
                                 const oca_callbacks_t *cb,
                                 oca_validation_context_t *ctx);

#endif /* OCA_CRYPTO_DISPATCH_H */

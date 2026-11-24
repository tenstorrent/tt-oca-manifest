// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Crypto callback dispatch for manifest_hash and signature_classic.
 */

#include "oca_validator.h"

#include "algorithms.h"
#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_variant.h"
#include "parser.h"
#include "secure_boot.h"

oca_result_t oca_check_manifest_hash(const uint8_t *body,
                                     const oca_callbacks_t *cb)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* Refused before hashing: a digest compared against one of another
     * algorithm would report a sound manifest as corrupt. */
    const oca_hash_algorithm_t *hash =
        oca_hash_algorithm(body[OCA_OFF_MANIFEST_HASH_TYPE], &status);
    if (hash == 0) {
        return status;
    }
    const size_t size = oca_hash_digest_size(hash);
    if (size == 0u) {
        return OCA_FAIL_MANIFEST_HASH;
    }
    if (cb == 0 || cb->hash == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    uint8_t digest[OCA_HASH_MAX_DIGEST_SIZE];
    oca_result_t r = cb->hash(hash->type, body,
                              v->signed_region_end, digest, size);
    if (r != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    /* Fixed-time compare (see oca_compare.h): both the digest match and the
     * trailing-padding check fold every byte before deciding. */
    const uint8_t *embedded = body + v->off_manifest_hash;
    if (oca_ct_diff(embedded, digest, size) != 0) {
        return OCA_FAIL_MANIFEST_HASH;
    }
    /* The rest of the 64-byte field, past the digest, must be zero. */
    if (oca_ct_any_nonzero(embedded + size, OCA_LEN_HASH_FIELD - size) != 0) {
        return OCA_FAIL_MANIFEST_HASH;
    }
    return OCA_OK;
}

#if !OCA_CFG_SECURE_BOOT_DISABLED
/**
 * @brief Verify one class's signature through the caller's verifier.
 *
 * Hands the verifier the class's signature and public key blobs as
 * oca_check_class_description() returns them, built from the values it
 * checked, with the signed region. Both classes verify over the same region,
 * [0, signed_region_end).
 *
 * @param[in] body  Whole variant body.
 * @param[in] v     Resolved variant descriptor; supplies the signed-region
 *                  extent.
 * @param[in] cb    Callback table. cb->verify_signature is checked here as well
 *                  as by the caller, so a path that skipped the caller's check
 *                  fails closed instead of calling through NULL — on a part
 *                  with code mapped at address zero, a jump into it.
 * @param[in] algo  Which class's signature to verify.
 * @retval OCA_OK                          The signature verified.
 * @retval OCA_FAIL_SIGNATURE              It did not — or the callback answered
 *                                         with a code it has no business
 *                                         returning, which is treated as a
 *                                         failure rather than silently passing
 *                                         the manifest.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   The verifier is not wired, or could
 *                                         not run.
 * @return Otherwise oca_check_class_description()'s refusal, checked here so
 *         the verifier is only ever handed an algorithm the build enables and
 *         the lengths that check held to their fields; else
 *         cb->verify_signature's verdict, normalized to the three codes above.
 */
static oca_result_t verify_signature_by_class(const uint8_t *body,
                                     const oca_variant_t *v,
                                     const oca_callbacks_t *cb,
                                     oca_key_algorithm_t algo)
{
    oca_class_blobs_t blobs;
    oca_result_t described = oca_check_class_description(body, algo, &blobs);
    if (described != OCA_OK) {
        return described;
    }
    if (cb == 0 || cb->verify_signature == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    oca_result_t r = cb->verify_signature(&blobs.signature, &blobs.public_key,
                                          body, v->signed_region_end);
    if (r == OCA_OK || r == OCA_FAIL_SIGNATURE
        || r == OCA_FAIL_CALLBACK_UNAVAILABLE) {
        return r;
    }
    return OCA_FAIL_SIGNATURE;
}
#endif /* !OCA_CFG_SECURE_BOOT_DISABLED */

oca_result_t oca_check_signature(const uint8_t *body,
                                 const oca_callbacks_t *cb,
                                 oca_validation_context_t *ctx)
{
#if OCA_CFG_SECURE_BOOT_DISABLED
    return oca_secure_boot_not_built(body, cb, ctx);
#else
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* Time-of-use confirmation of the secure-boot determination — the same
     * prologue the revocation and anti-rollback checks run. Only the intact
     * FALSE pattern skips verification. */
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        /* Nothing to verify. secure_boot_authenticated stays unset, which is
         * the distinction the encryption gate depends on. */
        return OCA_OK;
    }
    if (cb == 0 || cb->verify_signature == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* The recorded class enforcement is confirmed at time of use — one
     * glitched context word must not downgrade a hybrid manifest to
     * single-class verification. */
    oca_result_t classes = oca_secure_boot_confirm_classes(body, ctx);
    if (classes != OCA_OK) {
        return classes;
    }

    /* The device's posture comes before any signature: a context the posture
     * check did not vouch for is refused, so a hand-composed sequence cannot
     * verify a manifest that relies on a disabled algorithm or lacks a cohort
     * the device demands. */
    if (ctx->secure_boot_posture_met != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE_COHORT_REQUIRED;
    }

    /* Derived again here, independently of the confirm, for the final verdict
     * fold below. */
    uint8_t control = body[OCA_OFF_SECURE_BOOT_CONTROL];
    oca_secure_bool_t bit_classic =
        ((control & OCA_SECURE_BOOT_CLASSIC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    oca_secure_bool_t bit_pqc =
        ((control & OCA_SECURE_BOOT_PQC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;

    /* Per-class verdict words, folded into the final result below. Each class
     * block must SET its word — verified, or deliberately skipped — so the
     * zero initializer (neither secure-bool pattern) marks a block that was
     * glitched past rather than executed. Volatile so the fold is genuinely
     * computed at runtime instead of proven constant and optimized into a
     * plain store of TRUE. */
    volatile oca_secure_bool_t verified_classic = 0u;
    volatile oca_secure_bool_t verified_pqc     = 0u;

    /* --- CLASSICAL signature verification (when secure_boot_classic) ---
     * Gated on the classical key's own authorization flag: a key nothing
     * vouched for is never exercised. Skipped only on an exact
     * OCA_SECURE_FALSE, so a corrupted enforcement word runs a class's check
     * rather than skipping it. */
    if (ctx->secure_boot_enforce_classic != OCA_SECURE_FALSE) {
        if (ctx->secure_boot_key_authorized_classic != OCA_SECURE_TRUE) {
            return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
        }
        oca_result_t r = verify_signature_by_class(body, v, cb, OCA_KEY_ALGO_CLASSIC);
        if (r != OCA_OK) {
            return r;
        }
        verified_classic = OCA_SECURE_TRUE;    /* verified */
    } else {
        verified_classic = OCA_SECURE_FALSE;   /* deliberately skipped */
    }

    /* --- PQC signature verification (when secure_boot_pqc) ---
     * Same gate, on the PQC flag: a classical vouching never unlocks a PQC
     * verify. A variant with no PQC crypto region fails closed — the
     * structural invariant already rejects that manifest outright. */
    if (ctx->secure_boot_enforce_pqc != OCA_SECURE_FALSE) {
        if (ctx->manifest_is_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
        }
        if (ctx->secure_boot_key_authorized_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
        }
        oca_result_t r = verify_signature_by_class(body, v, cb, OCA_KEY_ALGO_PQC);
        if (r != OCA_OK) {
            return r;
        }
        verified_pqc = OCA_SECURE_TRUE;        /* verified */
    } else {
        verified_pqc = OCA_SECURE_FALSE;       /* deliberately skipped */
    }

    /* Branchless final verdict: reaching this line is not success — the VALUE
     * is. mismatch is zero only when each class verdict equals the manifest
     * bit that demanded it and at least one class was demanded, so a glitch
     * past any block above arrives here with a word the XOR turns into
     * neither secure-bool pattern, and every consumer of the flag compares
     * == OCA_SECURE_TRUE. Hybrid stays a logical AND; the encryption gate
     * reads this flag. */
    uint32_t mismatch = (verified_classic ^ bit_classic)
                      | (verified_pqc ^ bit_pqc)
                      | ((bit_classic ^ OCA_SECURE_TRUE)
                         & (bit_pqc ^ OCA_SECURE_TRUE));
    ctx->secure_boot_authenticated =
        (oca_secure_bool_t)(OCA_SECURE_TRUE ^ mismatch);

    /* Coherence check on the value just computed: a fold that did not come
     * out TRUE is a fault, and failing on it here costs an attacker a second,
     * independent glitch on top of whichever one poisoned it. */
    if (ctx->secure_boot_authenticated != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE;
    }
    return OCA_OK;
#endif /* !OCA_CFG_SECURE_BOOT_DISABLED */
}

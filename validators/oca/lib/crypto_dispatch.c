// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Crypto callback dispatch for manifest_hash and signature_classic.
 */

#include "crypto_dispatch.h"

#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "oca_variant.h"
#include "secure_boot.h"

oca_result_t oca_manifest_hash_check(const uint8_t *body,
                                     const oca_callbacks_t *cb)
{
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    if (cb == 0 || cb->sha256 == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    uint8_t digest[OCA_MANIFEST_HASH_DIGEST_SIZE];
    oca_result_t r = cb->sha256(body, v->signed_region_end,
                                digest);
    if (r != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    /* Fixed-time compare (see oca_compare.h): both the digest match and the
     * trailing-padding check fold every byte before deciding. */
    const uint8_t *embedded = body + v->off_manifest_hash;
    if (oca_ct_diff(embedded, digest, OCA_MANIFEST_HASH_DIGEST_SIZE) != 0) {
        return OCA_FAIL_MANIFEST_HASH;
    }
    /* The trailing 32 bytes of the 64-byte field must be zero. */
    if (oca_ct_any_nonzero(embedded + OCA_MANIFEST_HASH_DIGEST_SIZE,
                           OCA_LEN_MANIFEST_HASH - OCA_MANIFEST_HASH_DIGEST_SIZE) != 0) {
        return OCA_FAIL_MANIFEST_HASH;
    }
    return OCA_OK;
}

/**
 * @brief Verify one class's signature through the caller's verifier.
 *
 * Interface to the consumers siganature verification system. Encode a signature
 * and public key (per class; either classical or PQC) as full context blobs. Provides
 * those blobs as well as the signed data region over which to verify the signature.
 * Signature and public key blobs carry the same primitive algorithm type and class type
 * Both classes verify over the same signed region, [0, signed_region_end).
 *
 * @param[in] body  Whole variant body.
 * @param[in] v     Resolved variant descriptor. Supplies the two genuinely
 *                  variant-positioned values: the classical signature offset
 *                  and the signed-region extent. Every PQC field exists in
 *                  exactly one variant, so those offsets are the fixed
 *                  OCA_PQC_* constants.
 * @param[in] cb    Callback table. cb->verify_signature is non-NULL — the
 *                  caller fail-closes on an unwired verifier before any class
 *                  is verified.
 * @param[in] algo  Which class's signature to verify.
 * @retval OCA_OK                          The signature verified.
 * @retval OCA_FAIL_SIGNATURE              It did not — or the callback answered
 *                                         with a code it has no business
 *                                         returning, which is treated as a
 *                                         failure rather than silently passing
 *                                         the manifest.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   The verifier could not run.
 * @return cb->verify_signature's verdict, normalized to the three codes above.
 */
static oca_result_t verify_signature_by_class(const uint8_t *body,
                                     const oca_variant_t *v,
                                     const oca_callbacks_t *cb,
                                     oca_key_algorithm_t algo)
{
    const int is_pqc   = algo == OCA_KEY_ALGO_PQC;
    size_t off_type    = is_pqc ? (size_t)OCA_PQC_OFF_SIGNATURE_TYPE
                                : (size_t)OCA_OFF_SIGNATURE_TYPE;
    size_t off_sig_enc = is_pqc ? (size_t)OCA_PQC_OFF_SIGNATURE_ENCODING
                                : (size_t)OCA_OFF_SIGNATURE_ENCODING;
    size_t off_key_enc = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_ENCODING
                                : (size_t)OCA_OFF_PUBLIC_KEY_ENCODING;
    /* The one genuinely variant-positioned operand: signature_classic sits at
     * a different offset in each variant, so the classical arm reads the
     * descriptor. Everything else is a fixed constant for its class. */
    size_t off_sig     = is_pqc ? (size_t)OCA_PQC_OFF_SIGNATURE_PQC
                                : v->off_signature;
    size_t len_sig     = is_pqc ? (size_t)OCA_PQC_LEN_SIGNATURE_PQC
                                : (size_t)OCA_LEN_SIGNATURE;
    size_t off_key     = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY
                                : (size_t)OCA_OFF_PUBLIC_KEY;
    size_t len_key     = is_pqc ? (size_t)OCA_PQC_LEN_PUBLIC_KEY
                                : (size_t)OCA_LEN_PUBLIC_KEY;

    oca_primitive_type_t prim = (oca_primitive_type_t)body[off_type];

    oca_crypto_blob_t signature = {
        .bytes          = body + off_sig,
        .field_length   = len_sig,
        .kind           = OCA_BLOB_SIGNATURE,
        .encoding       = (oca_encoding_t)body[off_sig_enc],
        .primitive_type = prim,
        .key_algorithm  = algo,
    };
    oca_crypto_blob_t public_key = {
        .bytes          = body + off_key,
        .field_length   = len_key,
        .kind           = OCA_BLOB_PUBLIC_KEY,
        .encoding       = (oca_encoding_t)body[off_key_enc],
        .primitive_type = prim,
        .key_algorithm  = algo,
    };

    oca_result_t r = cb->verify_signature(&signature, &public_key,
                                          body, v->signed_region_end);
    if (r == OCA_OK || r == OCA_FAIL_SIGNATURE
        || r == OCA_FAIL_CALLBACK_UNAVAILABLE) {
        return r;
    }
    return OCA_FAIL_SIGNATURE;
}

oca_result_t oca_signature_check(const uint8_t *body,
                                 const oca_callbacks_t *cb,
                                 oca_validation_context_t *ctx)
{
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

    /* The recorded enforcement must still match the manifest's class bits —
     * one glitched context word must not downgrade a hybrid manifest to
     * single-class verification. */
    uint8_t control = body[OCA_OFF_SECURE_BOOT_CONTROL];
    oca_secure_bool_t bit_classic =
        ((control & OCA_SECURE_BOOT_CLASSIC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    oca_secure_bool_t bit_pqc =
        ((control & OCA_SECURE_BOOT_PQC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    if (ctx == 0
        || ctx->secure_boot_enforce_classic != bit_classic
        || ctx->secure_boot_enforce_pqc != bit_pqc) {
        return OCA_FAIL_SECURE_BOOT_STATE_CHANGED;
    }

    /* Engaged with no class enforced means the determination's rejection was
     * composed around by hand. Fail, never skip verification. */
    if (ctx->secure_boot_enforce_classic != OCA_SECURE_TRUE
        && ctx->secure_boot_enforce_pqc != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }

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
     * vouched for is never exercised. */
    if (ctx->secure_boot_enforce_classic == OCA_SECURE_TRUE) {
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
    if (ctx->secure_boot_enforce_pqc == OCA_SECURE_TRUE) {
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
}

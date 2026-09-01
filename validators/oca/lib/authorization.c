// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Secure-boot ROOT-key authorization check.
 *
 * The secure boot trust anchor reference. A manifest carries the public key its 
 * own signature is checked against, so verifying that signature establishes only 
 * that the holder of some private key produced this manifest: not that the 
 * Consumer trusts that key. Without this check, a key that signs its own manifest 
 * verifies, and secure boot decides nothing.
 *
 * Runs first of the key checks, before revocation and before any public-key
 * operation: an unknown key is refused without being used. Revocation then
 * narrows the authorized set, which is a different question asked second — a key
 * can be unauthorized without any revocation bit ever being set.
 *
 * The decision itself belongs to the Consumer, via cb->is_key_authorized. The
 * anchor is not something the manifest format can describe: it may be a key
 * embedded in mask ROM, a digest burned into OTP, an on-die table, or a chain
 * this build does not walk. The library supplies the key and the selection
 * bitmap, and holds no opinion on how they are judged.
 */

#include "oca_validator.h"

#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "secure_boot.h"

/**
 * @brief Present one class's ROOT key to the Consumer's trust anchor.
 *
 * Builds the key blob exactly as oca_check_signature() will present it — the
 * same offsets, the same encoding and primitive bytes, the same algorithm
 * family — so an implementation cannot end up authorizing one reading of a
 * field and verifying another.
 *
 * Every operand is at a fixed offset for its class: the classical key family
 * sits at shared offsets, and the PQC family exists in exactly one variant —
 * both arms of each selection are compile-time constants.
 *
 * @param[in] body  Whole variant body.
 * @param[in] cb    Callback table. cb->is_key_authorized is non-NULL — the
 *                  caller fail-closes on an unwired anchor before any class
 *                  is presented.
 * @param[in] algo  Which class's key to present.
 * @retval OCA_OK                          The device authorizes this key.
 * @retval OCA_FAIL_ROOT_KEY_UNAUTHORIZED  It does not — or the callback
 *                                         answered with a code it has no
 *                                         business returning, which is treated
 *                                         as a refusal rather than passed
 *                                         through as some unrelated verdict.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   The anchor could not be read.
 * @return cb->is_key_authorized's verdict, normalized to the three codes above.
 */
static oca_result_t authorize_key_by_class(const uint8_t *body,
                                        const oca_callbacks_t *cb,
                                        oca_key_algorithm_t algo)
{
    const int is_pqc  = algo == OCA_KEY_ALGO_PQC;
    size_t off_type   = is_pqc ? (size_t)OCA_PQC_OFF_SIGNATURE_TYPE
                               : (size_t)OCA_OFF_SIGNATURE_TYPE;
    size_t off_enc    = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_ENCODING
                               : (size_t)OCA_OFF_PUBLIC_KEY_ENCODING;
    size_t off_key    = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY
                               : (size_t)OCA_OFF_PUBLIC_KEY;
    size_t len_key    = is_pqc ? (size_t)OCA_PQC_LEN_PUBLIC_KEY
                               : (size_t)OCA_LEN_PUBLIC_KEY;
    size_t off_select = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_SELECT
                               : (size_t)OCA_OFF_PUBLIC_KEY_SELECT;

    oca_crypto_blob_t public_key = {
        .bytes          = body + off_key,
        .field_length   = len_key,
        .kind           = OCA_BLOB_PUBLIC_KEY,
        .encoding       = (oca_encoding_t)body[off_enc],
        .primitive_type = (oca_primitive_type_t)body[off_type],
        .key_algorithm  = algo,
    };

    oca_result_t r = cb->is_key_authorized(&public_key, body + off_select);
    if (r == OCA_OK || r == OCA_FAIL_CALLBACK_UNAVAILABLE) {
        return r;
    }
    return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
}

oca_result_t oca_check_root_key_authorized(const uint8_t *body,
                                           const oca_callbacks_t *cb,
                                           oca_validation_context_t *ctx)
{
    /* Engage only when secure boot is in force, and only once the device still
     * agrees with the determination this validation recorded. Same prologue as
     * the revocation, anti-rollback and signature checks. */
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }

    /* Fail closed. A build that never wired its trust anchor must not verify
     * anything, so this is deliberately not "no anchor means anything goes". */
    if (cb == 0 || cb->is_key_authorized == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* Confirm the recorded enforcement against the manifest bits it was read
     * from, exactly as the determination itself is confirmed at time of use:
     * a record and a re-derivation must still agree, or something changed one
     * of them since the determination — and one glitched context word must not
     * be able to downgrade a hybrid manifest to single-class verification. */
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

    /* Engaged with no class enforced is the policy the determination rejects
     * outright; a context here in that state can only have been composed by
     * hand around that rejection. Fail, never skip. */
    if (ctx->secure_boot_enforce_classic != OCA_SECURE_TRUE
        && ctx->secure_boot_enforce_pqc != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }

    /* Each enforced class is authorized against its OWN anchor and recorded in
     * its OWN flag, only after the callback returned success — never
     * optimistically ahead of the call. oca_check_signature() refuses to
     * exercise a key the matching flag does not vouch for, which is what makes
     * the ordering enforced rather than merely documented. */
    if (ctx->secure_boot_enforce_classic == OCA_SECURE_TRUE) {
        oca_result_t r = authorize_key_by_class(body, cb, OCA_KEY_ALGO_CLASSIC);
        if (r != OCA_OK) {
            return r;
        }
        ctx->secure_boot_key_authorized_classic = OCA_SECURE_TRUE;
    }
    if (ctx->secure_boot_enforce_pqc == OCA_SECURE_TRUE) {
        /* A non-PQC body has no PQC key to authorize. The determination never
         * settles a context in this state and the invariant rejects the
         * manifest outright; reaching here means both were composed around,
         * so fail the same way. Reads the confirmed variant record. */
        if (ctx->manifest_is_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
        }
        oca_result_t r = authorize_key_by_class(body, cb, OCA_KEY_ALGO_PQC);
        if (r != OCA_OK) {
            return r;
        }
        ctx->secure_boot_key_authorized_pqc = OCA_SECURE_TRUE;
    }
    return OCA_OK;
}

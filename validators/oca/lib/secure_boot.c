// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief The secure-boot determination: deciding it, recording it, confirming it.
 *
 * One precedence, in one place, reached three ways. oca_secure_boot_active()
 * asks it without side effects, oca_determine_secure_boot() asks it once and
 * writes the answer into a validation context, and oca_secure_boot_confirm()
 * asks it again to check the recorded answer still holds.
 */

#include "secure_boot.h"

#include "oca_layout.h"
#include "oca_variant.h"

/**
 * @brief Walk the secure-boot precedence, reporting which input decided.
 *
 * The precedence itself, and the only copy of it. Both the determination and
 * every confirm come through here, so there is no arrangement in which the
 * question gets asked two subtly different ways.
 *
 * Returning the device-disabled fact alongside the verdict is what keeps
 * deciding and recording ONE consultation of the device. Obtaining the verdict
 * here and then calling oca_secure_boot_device_disabled() again to fill in the
 * record would ask twice, and the two answers would be free to differ.
 *
 * Every value in here is an oca_secure_bool_t rather than a plain `bool`. The
 * question this answers is whether a signature gets verified, and there is no
 * point hardening the record in the context while the words the decision is
 * actually carried in are single bytes where zero means "skip the check".
 *
 * @param[in]  body                 Whole variant body.
 * @param[in]  cb                   Callback table. May be NULL.
 * @param[out] out_device_disabled  OCA_SECURE_TRUE only when input (2) was both
 *                                  REACHED and affirmative. A manifest that
 *                                  settles the question at (1) leaves this
 *                                  FALSE, so "not asked" and "answered no" are
 *                                  the same value — neither contributed to the
 *                                  verdict.
 * @return OCA_SECURE_TRUE when secure boot is in force for this boot,
 *         OCA_SECURE_FALSE otherwise.
 */
static oca_secure_bool_t secure_boot_decide(const uint8_t *body,
                                            const oca_callbacks_t *cb,
                                            oca_secure_bool_t *out_device_disabled)
{
    oca_secure_bool_t secure;

    *out_device_disabled = OCA_SECURE_FALSE;

    /* Three inputs, consulted in this order; the first to settle the question
     * decides it.
     *
     * 1. The manifest's secure_boot_control enable bit. FIRST, and deliberately
     *    so: an image built to be verified can only ever boot verified. Nothing
     *    a device reports downgrades it, which is what keeps a fault, a
     *    mis-provisioned fuse, or a defective reporter off the path to running a
     *    production image unverified. */
    if ((body[OCA_OFF_SECURE_BOOT_CONTROL] & OCA_SECURE_BOOT_ENFORCED_BIT) != 0u) {
        secure = OCA_SECURE_TRUE;
    }
    /* 2. A device asserting it is definitively not a secure-boot part —
     *    life-cycle state, a discrete disable fuse. The only input that can turn
     *    secure boot OFF. Reached only when the manifest has not already settled
     *    the question, so it can relax a requirement the device imposes, never
     *    one the image imposes.
     *
     *    Tested for the exact TRUE pattern: this is the branch that turns secure
     *    boot off, so it is the one no corrupted word may reach. */
    else if (oca_secure_boot_device_disabled(cb) == OCA_SECURE_TRUE) {
        *out_device_disabled = OCA_SECURE_TRUE;
        secure = OCA_SECURE_FALSE;
    }
    /* 3. The device's own view of whether secure boot is enforced.
     *
     *    Normalized, and note the direction. Only an exact OCA_SECURE_FALSE
     *    turns verification off here; a corrupted, uninitialized, or
     *    `return 1;`-style answer lands on ENFORCED. That is the same fail-safe
     *    the `else` below applies to an absent reporter, extended to a reporter
     *    that answered unintelligibly — the two cases deserve the same
     *    treatment, which a plain `bool` cannot give: there every nonzero byte
     *    is a confident "yes".
     *
     *    This is the MIRROR of the normalization in
     *    oca_secure_boot_device_disabled(), and deliberately so: there an
     *    unrecognized answer must not assert the disable, here it must not
     *    withdraw the enforcement. Both land on secure boot staying on.
     *
     *    More rides on this one than on its mirror, though. That one only has to
     *    keep a public return value honest — its caller re-tests for the exact
     *    pattern anyway. This value becomes ctx->secure_boot_enabled, the record
     *    every later confirm compares against and integrators read. Skip the
     *    normalization here and an unrecognized word is stored, compared, and
     *    handed out as this validation's verdict. */
    else if (cb != 0 && cb->is_secure_boot_active != 0) {
        secure = (cb->is_secure_boot_active() == OCA_SECURE_FALSE)
               ? OCA_SECURE_FALSE : OCA_SECURE_TRUE;
    }
    /* Unconfirmed secure boot defaults to enabled. The positive secure boot
     * callback reporter was not wired. Default to ACTIVE when an integrator
     * who has not affirmatively established "secure boot not enabled" gets
     * the secure path, not a silent bypass. */
    else {
        secure = OCA_SECURE_TRUE;
    }

    return secure;
}

oca_secure_bool_t oca_secure_boot_device_disabled(const oca_callbacks_t *cb)
{
    if (cb == 0 || cb->is_secure_boot_disabled == 0) {
        return OCA_SECURE_FALSE;
    }
    /* Only an exact OCA_SECURE_TRUE asserts the disable. Everything else — a
     * corrupted word, an integrator who wrote `return 1;` — reads as "not
     * asserted", which is what an absent reporter also means.
     *
     * This normalization is NOT what protects the determination. Its one
     * in-library caller compares `== OCA_SECURE_TRUE` itself, so an
     * unrecognized word misses the disable branch there with or without this
     * line. What it protects is the RETURN VALUE: this function is public, it is
     * documented to answer with one of two patterns, and integrators call it
     * directly to probe a part's provisioning. Handing back whatever the
     * callback happened to return would make that contract a lie and push the
     * problem into code the library cannot see.
     *
     * So: normalize where an outside value enters, and compare for the exact
     * pattern where a decision is made. Doing only the second leaves a public
     * function that lies; doing only the first leaves the decision resting on a
     * value some other translation unit produced. */
    return (cb->is_secure_boot_disabled() == OCA_SECURE_TRUE)
         ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
}

oca_secure_bool_t oca_secure_boot_active(const uint8_t *body,
                                         const oca_callbacks_t *cb)
{
    oca_secure_bool_t device_disabled;
    return secure_boot_decide(body, cb, &device_disabled);
}

oca_result_t oca_determine_secure_boot(const uint8_t *body,
                                       const oca_callbacks_t *cb,
                                       oca_validation_context_t *ctx)
{
    if (body == 0 || ctx == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    oca_secure_bool_t device_disabled;
    oca_secure_bool_t secure = secure_boot_decide(body, cb, &device_disabled);

    /* Recorded here, in the one function that owns the precedence, so the
     * context can only ever hold values this determination actually observed —
     * never a second, independently-obtained answer that could differ from the
     * one the decision was made on. Note that input (1) short-circuits before
     * the device is consulted, so secure_boot_device_disabled is left FALSE on
     * that path: "not asked" and "answered no" are the same recorded value,
     * because neither contributed to the verdict.
     *
     * Assigned rather than converted: the precedence already speaks in
     * oca_secure_bool_t, so the verdict reaches the record without passing
     * through a narrower type on the way. */
    ctx->secure_boot_enabled = secure;
    if (device_disabled == OCA_SECURE_TRUE) {
        ctx->secure_boot_device_disabled = OCA_SECURE_TRUE;
    }

    /* Which signature families verify this manifest as determined by the available
     * recorded in the same consultation that decided secure boot itself, so the
     * enforcement a later check acts on is the one this determination observed.
     * Normalized through the ternaries so only intact patterns are stored. */
    uint8_t control = body[OCA_OFF_SECURE_BOOT_CONTROL];

    /* The manifest variant flags are decided ONCE and recorded as a 
     * complementary pair. Exactly one of the two is TRUE in any settled context,
     * and they are always opposite patterns of each other. The secure-bool 
     * values are bitwise complements, so an intact pair XORs to all-ones and no
     * single corrupted word forges a coherent one. oca_secure_boot_confirm()
     * re-derives the class and refuses a record that drifts, so every
     * downstream consumer reads these instead of re-resolving the variant. */
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    oca_secure_bool_t is_pqc = (v->len_pqc_signature != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    ctx->manifest_is_pqc     = is_pqc;
    ctx->manifest_is_classic = (is_pqc == OCA_SECURE_TRUE)
        ? OCA_SECURE_FALSE : OCA_SECURE_TRUE;

    /* A PQC class bit on a variant with no PQC crypto region names an
     * enforcement no field can satisfy. The structural invariant rejects the
     * manifest for it; refusing to RECORD it here as well makes the state
     * unrepresentable through this writer — no settled context ever claims
     * PQC enforcement for a body the PQC checks would then misread. Returned
     * before secure_boot_determined is set, so ignoring the failure leaves an
     * unsettled context every gated check refuses. */
    if ((control & OCA_SECURE_BOOT_PQC_BIT) != 0u
        && is_pqc != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }

    ctx->secure_boot_enforce_classic =
        ((control & OCA_SECURE_BOOT_CLASSIC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    ctx->secure_boot_enforce_pqc =
        ((control & OCA_SECURE_BOOT_PQC_BIT) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;

    /* A manifest that demands verification while naming no signature class to
     * verify with describes a policy nothing can satisfy; the format requires
     * at least one class whenever secure boot is in force — whichever input
     * put it in force. Tested for the exact TRUE patterns, so only an intact
     * enforcement word can excuse the rejection.
     *
     * Returned BEFORE secure_boot_determined is set: a hand-composed sequence
     * that ignores this failure holds an unsettled context, and every gated
     * check refuses one — the rejection cannot be skipped past. */
    if (secure == OCA_SECURE_TRUE
        && ctx->secure_boot_enforce_classic != OCA_SECURE_TRUE
        && ctx->secure_boot_enforce_pqc != OCA_SECURE_TRUE) {
        return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
    }

    /* LAST, and only once the fields above are written. Every gated check tests
     * this before it will act at all, so it must never be observable while the
     * values it vouches for are half-written. Costs nothing, and removes a whole
     * class of "the context looked ready" reasoning from any future edit here. */
    ctx->secure_boot_determined = OCA_SECURE_TRUE;
    return OCA_OK;
}

oca_result_t oca_secure_boot_confirm(const uint8_t *body,
                                     const oca_callbacks_t *cb,
                                     const oca_validation_context_t *ctx,
                                     oca_secure_bool_t *out_engaged)
{
    if (body == 0 || out_engaged == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    /* Engaged is the value held until something affirmatively clears it. A fault
     * that skips any line below leaves the caller running its check, which is
     * the direction to fail in — and because this is an oca_secure_bool_t rather
     * than a bool, a fault that CLEARS the word does not skip either: zero is
     * not OCA_SECURE_FALSE, and only OCA_SECURE_FALSE skips. */
    *out_engaged = OCA_SECURE_TRUE;

    if (ctx == 0 || ctx->secure_boot_determined != OCA_SECURE_TRUE) {
        return OCA_FAIL_SECURE_BOOT_UNDETERMINED;
    }

    /* The recorded variant pair must still describe this body, and must still
     * be a pair. The two patterns are bitwise complements, so one XOR states
     * "exactly opposite": an intact pair XORs to all-ones; a flipped, copied,
     * or zeroed word does not. Every gated check runs this confirm, so no
     * consumer ever acts on a variant record the body disowns. */
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    oca_secure_bool_t live_pqc = (v->len_pqc_signature != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    if (ctx->manifest_is_pqc != live_pqc
        || (ctx->manifest_is_classic ^ ctx->manifest_is_pqc)
           != (OCA_SECURE_TRUE ^ OCA_SECURE_FALSE)) {
        return OCA_FAIL_SECURE_BOOT_STATE_CHANGED;
    }

    /* Re-walk the whole precedence, not just the device reporters: a glitched
     * manifest byte or a glitched branch inside the precedence is exactly as
     * capable of producing a wrong answer as a glitched fuse read. */
    oca_secure_bool_t observed = oca_secure_boot_active(body, cb);

    /* The record and the device must still agree. They disagree only if
     * something changed the answer between the determination and now — an
     * unstable reporter, or an induced fault. Neither is a state in which to
     * decide whether to verify a signature.
     *
     * Both sides are full-width hardened words, so this comparison also catches
     * a record corrupted into a value that is neither TRUE nor FALSE — the live
     * answer is always one of the two, so anything else can never match it. */
    if (ctx->secure_boot_enabled != observed) {
        return OCA_FAIL_SECURE_BOOT_STATE_CHANGED;
    }

    /* DELIBERATELY THE MIRROR OF THE COMPARISON ABOVE. Do not "fix" it.
     *
     * The rule on oca_secure_bool_t is to test equality against the pattern that
     * selects the LESS DEFENSIVE path, so no corrupted word can reach it. For
     * secure_boot_determined just above, and for secure_boot_authenticated, that
     * pattern is TRUE, because TRUE is what unlocks something. Here the less
     * defensive path is SKIPPING the caller's check, and FALSE is what selects
     * it — so FALSE is the pattern that must match exactly. Written
     * `!= OCA_SECURE_TRUE`, every corrupted word would skip the signature,
     * revocation, and anti-rollback checks in silence: precisely the bypass the
     * fail-safe default in secure_boot_decide() exists to prevent. */
    if (ctx->secure_boot_enabled == OCA_SECURE_FALSE) {
        *out_engaged = OCA_SECURE_FALSE;
    }
    return OCA_OK;
}

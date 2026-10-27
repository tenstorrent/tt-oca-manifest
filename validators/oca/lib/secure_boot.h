// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Internal helper for confirming a recorded secure-boot determination.
 *
 * The public determination and precedence functions are declared in
 * oca_validator.h. Only the confirm lives here, because only the library's own
 * checks use it.
 */

#ifndef OCA_SECURE_BOOT_H
#define OCA_SECURE_BOOT_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Re-derive the secure-boot determination and require it to match @p ctx.
 *
 * The single prologue every check that gates on secure boot runs before acting.
 * It answers two questions at once: is this context entitled to gate anything,
 * and does the device still say what it said when the determination was made.
 *
 * Re-deriving is the point. Reading the record alone would let one faulted
 * determination disarm every gated check at once; deriving independently at each
 * check, as this library once did, let one faulted read at a single check skip
 * that check alone with nothing to notice. Doing both means a fault has to be
 * consistent across the determination and every confirm to go undetected.
 *
 * The whole precedence is re-walked, not just the device reporters: a glitched
 * manifest byte or a glitched branch inside the precedence produces a wrong
 * answer exactly as readily as a glitched fuse read.
 *
 * @param[in]  body         Whole variant body.
 * @param[in]  cb           Callback table. May be NULL; both reporters are
 *                          optional and the precedence has a fail-safe default.
 * @param[in]  ctx          The determination to confirm against.
 * @param[out] out_engaged  Whether the caller's check applies. Set to
 *                          OCA_SECURE_TRUE before anything else, so a fault that
 *                          skips the logic below leaves the caller running its
 *                          check rather than waving the manifest through. Only
 *                          an intact recorded OCA_SECURE_FALSE clears it.
 *
 *                          Hardened rather than a plain `bool` because it is the
 *                          value that survives this call and decides whether a
 *                          signature gets verified. In a `bool` that decision is
 *                          one byte, and zero — the value a cleared byte holds —
 *                          is the answer that skips the check. Here zero is
 *                          neither TRUE nor FALSE, and the callers test for the
 *                          exact pattern that selects their own less defensive
 *                          path, so a corrupted word engages instead of skipping.
 * @retval OCA_OK                             @p out_engaged is meaningful.
 * @retval OCA_FAIL_INVALID_ARG               @p body or @p out_engaged was NULL.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx was NULL or holds no
 *                                            determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination disagrees
 *                                            with the recorded one — the
 *                                            secure-boot verdict, or the
 *                                            manifest variant pair, which must
 *                                            still describe this body and
 *                                            still be exact complements.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_secure_boot_confirm(const uint8_t *body,
                                     const oca_callbacks_t *cb,
                                     const oca_validation_context_t *ctx,
                                     oca_secure_bool_t *out_engaged);

/**
 * @brief Confirm the context's signature-class record against the manifest.
 *
 * Three checks, in order: the record matches the classic and PQC class bits of
 * the manifest's secure_boot_control byte; at least one class is enforced; and
 * the PQC class is enforced only on a PQC manifest.
 *
 * ROOT-key authorization, revocation, and signature verification each act once
 * per enforced class, reading which classes from the context, so the record is
 * confirmed at time of use exactly as the secure-boot determination is: one
 * glitched context word must not downgrade a hybrid manifest to single-class
 * verification. The device-state commit runs it too, because a record that the
 * signed class bits contradict means the body is not the one that validated.
 *
 * Call it only after oca_secure_boot_confirm() has reported secure boot engaged.
 * It does not itself check that @p ctx holds a determination, nor re-check the
 * variant record it reads for the PQC test; the confirm has done both.
 *
 * @param[in] body  Whole variant body.
 * @param[in] ctx   The determination being acted on.
 * @retval OCA_OK                             The record matches the manifest's
 *                                            class bits, enforces at least one
 *                                            class, and enforces the PQC class
 *                                            only on a PQC manifest.
 * @retval OCA_FAIL_INVALID_ARG               @p body was NULL.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED @p ctx was NULL, or its recorded
 *                                            enforcement disagrees with the
 *                                            manifest's class bits.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL   No class is enforced, or the PQC
 *                                            class is enforced on a body with
 *                                            no PQC fields. The determination
 *                                            never settles either state, so a
 *                                            context holding one was composed
 *                                            by hand around its rejection.
 */
oca_result_t oca_secure_boot_confirm_classes(const uint8_t *body,
                                             const oca_validation_context_t *ctx);

#endif /* OCA_SECURE_BOOT_H */

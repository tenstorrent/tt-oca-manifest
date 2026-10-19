// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Secure-boot ROOT-key revocation check.
 *
 * Before a selected ROOT key is used to verify the manifest signature, confirm
 * it is not revoked. Each signature class the manifest enforces is checked
 * against its own algorithm family's state, because the device keeps classic
 * and PQC revocation separately: the effective revocation set for a class is
 * the union of the manifest's revocation bitmap for that class and the
 * device-stored state for its family (read via the host callback). A selected
 * key is revoked if any of its select bits overlaps that set. Every bitmap is
 * 128 bits wide, and the top 16 (bytes 14..15) are reserved and ignored.
 */

#include "oca_validator.h"

#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "secure_boot.h"

/**
 * @brief Reject one class's selected ROOT key if its family's state revokes it.
 *
 * Both operands are at fixed offsets for their class: the classical family at
 * shared offsets, the PQC family in the one variant that carries it.
 *
 * @param[in] body  Whole variant body; a PQC body when @p algo is
 *                  OCA_KEY_ALGO_PQC.
 * @param[in] cb    Callback table; cb->get_root_key_revocation is non-NULL.
 * @param[in] algo  Which class's key, and which family's state, to check.
 * @retval OCA_OK                         The selected key is not revoked.
 * @retval OCA_FAIL_ROOT_KEY_REVOKED      A selected key bit is revoked.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE  The family's device state could not
 *                                        be read.
 */
static oca_result_t check_revocation_by_class(const uint8_t *body,
                                              const oca_callbacks_t *cb,
                                              oca_key_algorithm_t algo)
{
    const int is_pqc  = algo == OCA_KEY_ALGO_PQC;
    size_t off_select = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_SELECT
                               : (size_t)OCA_OFF_PUBLIC_KEY_SELECT;
    size_t off_revoke = is_pqc ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_REVOKE
                               : (size_t)OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE;

    /* Pre-filled with every key revoked, so a reader that reports success
     * without writing fails closed instead of leaving stack contents to
     * decide. */
    uint8_t device_revoke[OCA_LEN_ROOT_KEY_BITMAP];
    for (unsigned i = 0u; i < OCA_LEN_ROOT_KEY_BITMAP; ++i) {
        device_revoke[i] = 0xFFu;
    }
    if (cb->get_root_key_revocation(algo, device_revoke) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    const uint8_t *select          = body + off_select;
    const uint8_t *manifest_revoke = body + off_revoke;

    /* Reject if a selected key bit overlaps the effective (manifest | device)
     * revocation set. Only the used bytes (0..13 = bits 0..111) are compared;
     * bytes 14..15 (bits 127:112) are reserved and ignored. Folded in fixed time
     * (see oca_compare.h) so the timing does not reveal which key slot revoked. */
    uint8_t effective[OCA_ROOT_KEY_BITMAP_USED_BYTES];
    for (unsigned i = 0u; i < OCA_ROOT_KEY_BITMAP_USED_BYTES; ++i) {
        effective[i] = (uint8_t)(manifest_revoke[i] | device_revoke[i]);
    }
    if (oca_ct_any_overlap(select, effective, OCA_ROOT_KEY_BITMAP_USED_BYTES) != 0) {
        return OCA_FAIL_ROOT_KEY_REVOKED;
    }
    return OCA_OK;
}

oca_result_t oca_check_root_key_revocation(const uint8_t *body,
                                           const oca_callbacks_t *cb,
                                           const oca_validation_context_t *ctx)
{
    /* Engage only when secure boot is in force, and only once the device still
     * agrees with the determination this validation recorded. Same prologue as
     * the signature and anti-rollback checks. */
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }
    if (cb == 0 || cb->get_root_key_revocation == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* Which keys are checked follows the recorded class enforcement, so the
     * record is confirmed first: a glitched context word must not skip the
     * revocation check for a key the signature check will still exercise. */
    oca_result_t classes = oca_secure_boot_confirm_classes(body, ctx);
    if (classes != OCA_OK) {
        return classes;
    }

    if (ctx->secure_boot_enforce_classic == OCA_SECURE_TRUE) {
        oca_result_t r = check_revocation_by_class(body, cb, OCA_KEY_ALGO_CLASSIC);
        if (r != OCA_OK) {
            return r;
        }
    }
    if (ctx->secure_boot_enforce_pqc == OCA_SECURE_TRUE) {
        /* Never read PQC offsets out of a body that has none. The confirm
         * above already refused this; it is repeated at the point of use. */
        if (ctx->manifest_is_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
        }
        oca_result_t r = check_revocation_by_class(body, cb, OCA_KEY_ALGO_PQC);
        if (r != OCA_OK) {
            return r;
        }
    }
    return OCA_OK;
}

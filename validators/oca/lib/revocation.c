// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Secure-boot ROOT-key revocation check.
 *
 * Before the selected ROOT key is used to verify the manifest signature, confirm
 * it is not revoked. The effective revocation set is the union of the manifest's
 * public_key_classic_revoke bitmap and the device-stored classic revocation state
 * (read via the host callback). A selected key is revoked if any of its
 * public_key_select_classic bits overlaps that set. Both are 128-bit bitmaps
 * whose top 16 bits (bytes 14..15) are reserved and ignored.
 */

#include "oca_validator.h"

#include "oca_compare.h"
#include "oca_layout.h"
#include "secure_boot.h"

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

    uint8_t device_revoke[OCA_LEN_PUBLIC_KEY_CLASSIC_REVOKE];
    if (cb->get_root_key_revocation(OCA_KEY_ALGO_CLASSIC, device_revoke) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    const uint8_t *select          = body + OCA_OFF_PUBLIC_KEY_SELECT;
    const uint8_t *manifest_revoke = body + OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE;

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

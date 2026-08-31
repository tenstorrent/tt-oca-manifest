// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Identity-byte comparison against caller-supplied hardware values.
 *
 * The library never reads hardware; it asks the callback.
 */

#include "identity.h"

#include "oca_compare.h"
#include "oca_layout.h"

/**
 * @brief Map an identity kind to the failure code a mismatch reports.
 *
 * Keeps the three identity checks on one code path while still reporting which
 * field actually failed — a field diagnosis is only useful if it names the
 * field.
 *
 * @param[in] kind  Identity kind to map.
 * @retval OCA_FAIL_CHIPLET_ID   @p kind was OCA_ID_CHIPLET.
 * @retval OCA_FAIL_PACKAGE_ID   @p kind was OCA_ID_PACKAGE.
 * @retval OCA_FAIL_SYSTEM_ID    @p kind was OCA_ID_SYSTEM.
 * @retval OCA_FAIL_INVALID_ARG  @p kind was outside the enumeration. The switch
 *                               above covers every enumerator, so this is
 *                               defence against a corrupted value rather than a
 *                               reachable branch.
 */
static oca_result_t map_kind_to_fail(oca_id_kind_t kind)
{
    switch (kind) {
        case OCA_ID_CHIPLET: return OCA_FAIL_CHIPLET_ID;
        case OCA_ID_PACKAGE: return OCA_FAIL_PACKAGE_ID;
        case OCA_ID_SYSTEM:  return OCA_FAIL_SYSTEM_ID;
    }
    return OCA_FAIL_INVALID_ARG;
}

oca_result_t oca_identity_compare(const uint8_t *body,
                                  unsigned       field_offset,
                                  oca_id_kind_t  kind,
                                  uint32_t       mask,
                                  const oca_callbacks_t *cb)
{
    if (mask == 0u) {
        return OCA_OK;
    }
    if (cb == 0 || cb->get_identity_bytes == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    uint8_t hw[OCA_LEN_IDENTITY];
    oca_hw_result_t r = cb->get_identity_bytes(kind, hw);
    if (r != OCA_HW_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* Fixed-time masked compare (see oca_compare.h). This weighs manifest bytes
     * against values read out of hardware, so neither the number of matching
     * bytes nor which byte positions the selector enabled should be observable
     * in the timing. */
    const oca_result_t fail_code = map_kind_to_fail(kind);
    if (oca_ct_diff_masked(body + field_offset, hw, OCA_LEN_IDENTITY, mask) != 0) {
        return fail_code;
    }
    return OCA_OK;
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Lifecycle-state bitmap check.
 *
 * The manifest's lifecycle_<level>_states field is a 32-bit bitmap. The
 * caller-supplied callback reports the hardware's current lifecycle
 * state as one of the OCA_LIFECYCLE_* enumerators; we test whether the
 * bit at that position is set in the manifest's bitmap.
 */

#include "lifecycle.h"

#include "oca_layout.h"
#include "parser.h"

/**
 * @brief Offset of the lifecycle-states bitmap for a level.
 *
 * The three bitmaps sit at fixed, unrelated offsets, so the lookup is a switch
 * rather than arithmetic on the level.
 *
 * @param[in] level  Which level's bitmap to locate.
 * @return Byte offset within the manifest body. Zero for a level outside the
 *         enumeration — unreachable through the enum, and harmless because the
 *         caller only reads a bitmap it was going to compare anyway.
 */
static unsigned level_offset(oca_lifecycle_level_t level)
{
    switch (level) {
        case OCA_LIFECYCLE_LEVEL_CHIPLET:
            return OCA_OFF_LIFECYCLE_CHIPLET_STATES;
        case OCA_LIFECYCLE_LEVEL_PACKAGE:
            return OCA_OFF_LIFECYCLE_PACKAGE_STATES;
        case OCA_LIFECYCLE_LEVEL_SYSTEM:
            return OCA_OFF_LIFECYCLE_SYSTEM_STATES;
    }
    return 0u;
}

oca_result_t oca_lifecycle_check(const uint8_t *body,
                                 oca_lifecycle_level_t level,
                                 const oca_callbacks_t *cb)
{
    uint32_t bitmap = oca_le_u32(body + level_offset(level));

    /* Reserved bits [31:7] are ignored, not rejected: v2 lets a future minor
     * repurpose them and forbids the Consumer from acting on reserved fields
     * (see oca_check_reserved_bits). The membership test below only inspects
     * bits [6:0], so a set reserved bit does not affect the decision. */

    if (cb == 0 || cb->get_lifecycle_state == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    oca_lifecycle_token_t hw_state = OCA_LIFECYCLE_UNKNOWN;
    oca_hw_result_t r = cb->get_lifecycle_state(level, &hw_state);
    if (r != OCA_HW_OK || hw_state == OCA_LIFECYCLE_UNKNOWN) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* Token is a bit position 0..6; check membership in the bitmap. */
    if (((bitmap >> (unsigned)hw_state) & 1u) == 0u) {
        return OCA_FAIL_LIFECYCLE;
    }
    return OCA_OK;
}

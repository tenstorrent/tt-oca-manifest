/**
 * @file
 * @brief Version-range comparison.
 *
 * Each 8-byte version_range field packs:
 *   bytes[0..2] minor_min (LE u16)
 *   bytes[2..4] major_min (LE u16)
 *   bytes[4..6] minor_max (LE u16)
 *   bytes[6..8] major_max (LE u16)
 *
 * The "specified" booleans come from the selector_bits enable bits
 * (99..104). Tuple ordering is lexicographic by (major, minor).
 */

#include "version_range.h"

#include "oca_layout.h"
#include "parser.h"

/**
 * @brief Offset of the version-range field for a level.
 *
 * The three ranges sit at fixed, unrelated offsets, so the lookup is a switch
 * rather than arithmetic on the level.
 *
 * @param[in] level  Which level's range to locate.
 * @return Byte offset within the manifest body. Zero for a level outside the
 *         enumeration, which the enum makes unreachable.
 */
static unsigned level_offset(oca_version_level_t level)
{
    switch (level) {
        case OCA_VERSION_LEVEL_CHIPLET:
            return OCA_OFF_VERSION_RANGE_CHIPLET;
        case OCA_VERSION_LEVEL_PACKAGE:
            return OCA_OFF_VERSION_RANGE_PACKAGE;
        case OCA_VERSION_LEVEL_SYSTEM:
            return OCA_OFF_VERSION_RANGE_SYSTEM;
    }
    return 0u;
}

/**
 * @brief Order two (major, minor) version pairs lexicographically.
 *
 * Major dominates: 2.0 is newer than 1.99. Comparing the pair as one ordered
 * value is what makes both range bounds a single test rather than four
 * interacting ones.
 *
 * @param[in] a_major  Left-hand major.
 * @param[in] a_minor  Left-hand minor.
 * @param[in] b_major  Right-hand major.
 * @param[in] b_minor  Right-hand minor.
 * @return true when (a_major, a_minor) <= (b_major, b_minor).
 */
static bool tuple_le(uint16_t a_major, uint16_t a_minor,
                     uint16_t b_major, uint16_t b_minor)
{
    if (a_major < b_major) return true;
    if (a_major > b_major) return false;
    return a_minor <= b_minor;
}

oca_result_t oca_version_range_check(const uint8_t *body,
                                     oca_version_level_t level,
                                     bool min_specified,
                                     bool max_specified,
                                     const oca_callbacks_t *cb)
{
    if (!min_specified && !max_specified) {
        return OCA_OK;
    }
    if (cb == 0 || cb->get_version == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    uint16_t hw_major = 0;
    uint16_t hw_minor = 0;
    oca_hw_result_t r = cb->get_version(level, &hw_major, &hw_minor);
    if (r != OCA_HW_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    const uint8_t *f = body + level_offset(level);
    if (min_specified) {
        uint16_t minor_min = oca_le_u16(f + OCA_VR_OFF_MINOR_MIN);
        uint16_t major_min = oca_le_u16(f + OCA_VR_OFF_MAJOR_MIN);
        if (!tuple_le(major_min, minor_min, hw_major, hw_minor)) {
            return OCA_FAIL_VERSION_RANGE;
        }
    }
    if (max_specified) {
        uint16_t minor_max = oca_le_u16(f + OCA_VR_OFF_MINOR_MAX);
        uint16_t major_max = oca_le_u16(f + OCA_VR_OFF_MAJOR_MAX);
        if (!tuple_le(hw_major, hw_minor, major_max, minor_max)) {
            return OCA_FAIL_VERSION_RANGE;
        }
    }
    return OCA_OK;
}

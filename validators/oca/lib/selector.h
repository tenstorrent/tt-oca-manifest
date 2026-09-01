// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Internal helpers for decoding the 16-byte selector_bits region and
 * checking its reserved-bit constraint.
 */

#ifndef OCA_SELECTOR_H
#define OCA_SELECTOR_H

#include <stdbool.h>
#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Decoded view of the manifest's 16-byte selector_bits field.
 *
 * Says which constraints a manifest actually asserts. Everything the validation
 * sequence decides about whether to consult hardware comes from here, so
 * decoding once into named fields keeps bit arithmetic out of the check
 * functions.
 */
typedef struct oca_selector_bits {
    uint32_t chiplet_id_mask;             /**< Bits 0..31: which chiplet-ID bytes must match. */
    uint32_t package_id_mask;             /**< Bits 32..63: which package-ID bytes must match. */
    uint32_t system_id_mask;              /**< Bits 64..95: which system-ID bytes must match. */
    bool     lifecycle_chiplet_enabled;   /**< Bit 96: chiplet lifecycle is constrained. */
    bool     lifecycle_package_enabled;   /**< Bit 97: package lifecycle is constrained. */
    bool     lifecycle_system_enabled;    /**< Bit 98: system lifecycle is constrained. */
    bool     version_chiplet_min_enabled; /**< Bit 99: chiplet version has a floor. */
    bool     version_chiplet_max_enabled; /**< Bit 100: chiplet version has a ceiling. */
    bool     version_package_min_enabled; /**< Bit 101: package version has a floor. */
    bool     version_package_max_enabled; /**< Bit 102: package version has a ceiling. */
    bool     version_system_min_enabled;  /**< Bit 103: system version has a floor. */
    bool     version_system_max_enabled;  /**< Bit 104: system version has a ceiling. */
    /** Any bit in 105..127 is set — the manifest asserts a constraint this
     *  build does not implement, which is a rejection rather than something to
     *  ignore. */
    bool     reserved_bits_set;
} oca_selector_bits_t;

/**
 * @brief Decode the manifest's selector_bits into named fields.
 *
 * Reads the 16 bytes at body + OCA_OFF_SELECTOR_BITS. A pure function that
 * cannot fail: every bit pattern decodes to some valid combination, and
 * deciding whether that combination is acceptable belongs to the checks that
 * consume it — notably the reserved-bit rejection.
 *
 * @param[in]  body  Whole variant body.
 * @param[out] out   Receives the decoded view. Every field is written.
 */
void oca_selector_decode(const uint8_t *body, oca_selector_bits_t *out);

/**
 * @brief Report whether a manifest asserts any constraint at all.
 *
 * Used by oca_validate() to skip callback dispatch entirely on a permissive
 * manifest, so an unconstrained bundle costs no hardware reads.
 *
 * Reserved bits count as a constraint. That is deliberate: a manifest asserting
 * something this build cannot interpret must not be treated as permissive.
 *
 * @param[in] s  Decoded selector bits.
 * @return true when `chiplet_id_mask`, `package_id_mask`, `system_id_mask`, any
 *         lifecycle or version enable, or `reserved_bits_set` is set; false when
 *         the manifest constrains nothing.
 */
bool oca_selector_any_constraint_enabled(const oca_selector_bits_t *s);

#endif /* OCA_SELECTOR_H */

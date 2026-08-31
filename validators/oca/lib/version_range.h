// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Compare the hardware's current version against the manifest's min/max
 * range halves.
 */

#ifndef OCA_VERSION_RANGE_H
#define OCA_VERSION_RANGE_H

#include <stdbool.h>
#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Confirm the hardware version falls inside the manifest's range.
 *
 * Backs oca_check_version_range(). The two halves of the range are enabled
 * independently by selector_bits, so a manifest can set a floor without a
 * ceiling or the reverse. When neither half is specified this returns OCA_OK
 * without invoking the callback, so an unconstrained level costs no hardware
 * read.
 *
 * @param[in] body            Whole variant body.
 * @param[in] level           Which level's version to check.
 * @param[in] min_specified   Whether the minimum half is enabled.
 * @param[in] max_specified   Whether the maximum half is enabled.
 * @param[in] cb              Callback table; cb->get_version is required when
 *                            either half is enabled.
 * @retval OCA_OK                          In range, or neither half specified.
 * @retval OCA_FAIL_VERSION_RANGE          Reported version is outside the range.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Callback missing or unavailable.
 */
oca_result_t oca_version_range_check(const uint8_t *body,
                                     oca_version_level_t level,
                                     bool min_specified,
                                     bool max_specified,
                                     const oca_callbacks_t *cb);

#endif /* OCA_VERSION_RANGE_H */

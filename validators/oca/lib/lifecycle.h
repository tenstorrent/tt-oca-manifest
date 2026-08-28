/**
 * @file
 * @brief Compare a lifecycle-states bitmap against the hardware's current
 * lifecycle token.
 *
 * Internal header.
 */

#ifndef OCA_LIFECYCLE_H
#define OCA_LIFECYCLE_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Confirm the hardware's lifecycle token is permitted at a level.
 *
 * Backs oca_check_lifecycle(). The manifest carries a bitmap of acceptable
 * states per level; this reads the device's current token and confirms its bit
 * is set. A token the manifest does not list — including
 * OCA_LIFECYCLE_UNKNOWN — fails.
 *
 * @param[in] body   Whole variant body.
 * @param[in] level  Which level's lifecycle bitmap to check.
 * @param[in] cb     Callback table; cb->get_lifecycle_state is required.
 * @retval OCA_OK                          Reported state is permitted.
 * @retval OCA_FAIL_LIFECYCLE              Reported state is not permitted.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Callback missing or unavailable.
 */
oca_result_t oca_lifecycle_check(const uint8_t *body,
                                 oca_lifecycle_level_t level,
                                 const oca_callbacks_t *cb);

#endif /* OCA_LIFECYCLE_H */

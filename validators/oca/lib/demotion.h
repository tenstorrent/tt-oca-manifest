/**
 * @file
 * @brief demotion_control stage.
 *
 * demotion_control is a directive to the boot ROM, not a constraint, so there
 * is no hardware-side comparison. Its reserved bits [15:4] are ignored rather
 * than rejected (v2: the Consumer shall not act on reserved fields, and
 * reserved regions are available for minor-version extension), so this stage
 * is a no-op on the host validator.
 */

#ifndef OCA_DEMOTION_H
#define OCA_DEMOTION_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Demotion-control stage. Always passes, by design.
 *
 * Backs oca_check_demotion_control(). demotion_control directs the boot ROM
 * rather than constraining the device, so there is nothing here to compare and
 * no callback to consult: the operative bits [3:0] are consumed device-side and
 * the reserved bits [15:4] are ignored rather than rejected. Retained as a
 * documented no-op for API and pipeline stability.
 *
 * @param[in] body  Unused. Accepted so the signature matches the other checks.
 * @retval OCA_OK  Always.
 */
oca_result_t oca_demotion_check(const uint8_t *body);

#endif /* OCA_DEMOTION_H */

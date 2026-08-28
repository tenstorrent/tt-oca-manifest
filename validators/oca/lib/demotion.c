/**
 * @file
 * @brief demotion_control stage (no-op).
 *
 * demotion_control carries an operative directive in bits [3:0] that the boot
 * ROM consumes device-side, plus reserved bits [15:4]. The host validator no
 * longer rejects set reserved bits (see oca_check_reserved_bits for the v2
 * rationale), and it does not act on the device-side directive, so this stage
 * is a no-op retained for API/pipeline stability.
 */

#include "demotion.h"

oca_result_t oca_demotion_check(const uint8_t *body)
{
    /* demotion_control's reserved bits [15:4] are Producer-zeroed and reserved
     * for backward-compatible minor-version extension. Per v2 the Consumer
     * shall not reject a manifest for a set reserved bit and shall not act on
     * reserved fields (see oca_check_reserved_bits); the operative demotion
     * bits [3:0] are consumed device-side, not by this host validator. Retained
     * as a documented no-op for API/pipeline stability. */
    (void)body;
    return OCA_OK;
}

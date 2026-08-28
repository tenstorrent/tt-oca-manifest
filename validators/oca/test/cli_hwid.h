/*
 * cli_hwid.h — Hardware-identity callbacks backed by CLI flags.
 *
 * The validator's readback callbacks stand in for silicon that a host tool does
 * not have, so their answers come from command-line flags instead. Bind the
 * parsed options once with cli_hwid_bind(); the callbacks read them from there.
 */

#ifndef OCA_CLI_HWID_H
#define OCA_CLI_HWID_H

#include "cli_args.h"
#include "oca_validator.h"

/**
 * @brief Point the readback callbacks at the parsed command-line options.
 *
 * Call once before validating. The callbacks below report OCA_HW_UNAVAILABLE
 * until this has been called, which the validator treats as a hard failure —
 * so a forgotten bind fails the run rather than silently reporting zeros.
 *
 * @param[in] opt  Parsed options. Borrowed, not copied: it must outlive the
 *                 validation. NULL unbinds.
 */
void cli_hwid_bind(const cli_options_t *opt);

oca_hw_result_t cli_get_identity_bytes(oca_id_kind_t field,
                                       uint8_t out[32]);

oca_hw_result_t cli_get_lifecycle_state(oca_lifecycle_level_t level,
                                        oca_lifecycle_token_t *out_state);

oca_hw_result_t cli_get_version(oca_version_level_t level,
                                uint16_t *out_major,
                                uint16_t *out_minor);
oca_result_t cli_is_key_authorized(const oca_crypto_blob_t *public_key,
                                   const uint8_t select[16]);

#endif /* OCA_CLI_HWID_H */

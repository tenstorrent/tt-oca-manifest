/**
 * @file
 * @brief Compare an identity field's selected bytes against the
 * hardware-reported identity bytes.
 *
 * Internal header.
 */

#ifndef OCA_IDENTITY_H
#define OCA_IDENTITY_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Compare selected identity bytes against the hardware's reported value.
 *
 * Backs oca_check_identity() for all three identity kinds. Only the bytes
 * @p mask selects participate, so a manifest can pin part of an identity and
 * leave the rest free.
 *
 * @param[in] body          Whole variant body.
 * @param[in] field_offset  Offset of the 32-byte identity region within @p body.
 * @param[in] kind          Which identity this is, used to pick the failure code
 *                          and to ask the callback for the matching value.
 * @param[in] mask          Selects which of the 32 bytes must match.
 * @param[in] cb            Callback table; cb->get_identity_bytes is required.
 * @retval OCA_OK                          Every selected byte matched.
 * @retval OCA_FAIL_CHIPLET_ID             Mismatch, @p kind was chiplet.
 * @retval OCA_FAIL_PACKAGE_ID             Mismatch, @p kind was package.
 * @retval OCA_FAIL_SYSTEM_ID              Mismatch, @p kind was system.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Callback missing or unavailable.
 * @return Otherwise the code mapped from @p kind for a mismatch.
 */
oca_result_t oca_identity_compare(const uint8_t *body,
                                  unsigned       field_offset,
                                  oca_id_kind_t  kind,
                                  uint32_t       mask,
                                  const oca_callbacks_t *cb);

#endif /* OCA_IDENTITY_H */

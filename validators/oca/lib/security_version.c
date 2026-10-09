// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Secure-boot anti-rollback security-version check and the post-verify
 * device-state commit.
 *
 * manifest_security_version is a 128-bit flag field. The anti-rollback check
 * requires it to be a bit-superset of the device-stored value: every flag set on
 * the device must also be set in the manifest, i.e. (device & ~manifest) == 0.
 *
 * The commit advances device state after a successful validation: it bitwise-ORs
 * the manifest's revocation bitmap, security-version flags, and signature
 * posture registers into the device-stored values (setting bits only, never
 * clearing), unless suppressed by the manifest_security_control disable bits.
 */

#include "oca_validator.h"

#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "parser.h"
#include "secure_boot.h"

oca_result_t oca_check_security_version(const uint8_t *body,
                                        const oca_callbacks_t *cb,
                                        const oca_validation_context_t *ctx)
{
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }
    if (cb == 0 || cb->get_security_version == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    uint8_t device[OCA_LEN_MANIFEST_SECURITY_VERSION];
    if (cb->get_security_version(device) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* A device flag the manifest does not carry is a rollback: (device & ~manifest)
     * must be zero. Folded in fixed time (see oca_compare.h) so the timing does
     * not reveal which flag position failed. */
    const uint8_t *manifest = body + OCA_OFF_MANIFEST_SECURITY_VERSION;
    uint8_t missing[OCA_LEN_MANIFEST_SECURITY_VERSION];
    for (unsigned i = 0u; i < OCA_LEN_MANIFEST_SECURITY_VERSION; ++i) {
        missing[i] = (uint8_t)(device[i] & (uint8_t)~manifest[i]);
    }
    if (oca_ct_any_nonzero(missing, sizeof missing) != 0) {
        return OCA_FAIL_SECURITY_VERSION;
    }
    return OCA_OK;
}

/**
 * @brief OR one family's manifest revocation bitmap into that family's device
 *        state.
 *
 * The device keeps classic and PQC revocation separately, so each family's
 * device bitmap is read, OR-ed with the manifest field for the same family, and
 * written back through the callbacks keyed on that family alone. The whole
 * 16-byte field is OR-ed, reserved bits included.
 *
 * @param[in] body  Whole variant body; a PQC body when @p algo is
 *                  OCA_KEY_ALGO_PQC.
 * @param[in] cb    Callback table; cb->get_root_key_revocation and
 *                  cb->set_root_key_revocation are non-NULL.
 * @param[in] algo  Which family's manifest bitmap and device state to commit.
 * @retval OCA_OK                          The family's state was written.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   The family's state could not be read.
 * @retval OCA_FAIL_SECURITY_STATE_UPDATE  The write-back failed.
 */
static oca_result_t commit_revocation_for_family(const uint8_t *body,
                                               const oca_callbacks_t *cb,
                                               oca_key_algorithm_t algo)
{
    size_t off_revoke = (algo == OCA_KEY_ALGO_PQC)
                            ? (size_t)OCA_PQC_OFF_PUBLIC_KEY_REVOKE
                            : (size_t)OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE;

    uint8_t device[OCA_LEN_ROOT_KEY_BITMAP];
    if (cb->get_root_key_revocation(algo, device) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    const uint8_t *manifest = body + off_revoke;
    for (unsigned i = 0u; i < OCA_LEN_ROOT_KEY_BITMAP; ++i) {
        device[i] = (uint8_t)(device[i] | manifest[i]);
    }
    if (cb->set_root_key_revocation(algo, device) != OCA_OK) {
        return OCA_FAIL_SECURITY_STATE_UPDATE;
    }
    return OCA_OK;
}

oca_result_t oca_commit_security_state(const uint8_t *body,
                                       const oca_callbacks_t *cb,
                                       const oca_validation_context_t *ctx)
{
    /* Confirmed before anything is written, not after. Every path out of this
     * function below burns fuses, and a determination that no longer matches the
     * device is not a basis on which to make an irreversible change. */
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }

    /* The class record must still describe this body. Its class bits are
     * signed, so a record that disagrees with them means the body is not the
     * one that validated — no basis for an irreversible write. */
    oca_result_t classes = oca_secure_boot_confirm_classes(body, ctx);
    if (classes != OCA_OK) {
        return classes;
    }

    /* Read as u16: bits 4 and 5 govern the signature posture registers below, so
     * a single-byte load would silently ignore any control bit above 7. */
    uint16_t control = oca_le_u16(body + OCA_OFF_MANIFEST_SECURITY_CONTROL);

    /* ROOT-key revocation OR-in, unless suppressed (bit 1): every revocation
     * bitmap the manifest carries, whichever signature class authenticated it —
     * the classic one always, the PQC one on a PQC manifest. Keyed on the
     * confirmed variant record, so no PQC offset is read from a body without
     * PQC fields. */
    if ((control & OCA_SECURITY_CONTROL_REVOKE_KEYS_DISABLE_BIT) == 0u) {
        if (cb == 0 || cb->get_root_key_revocation == 0
            || cb->set_root_key_revocation == 0) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        oca_result_t r = commit_revocation_for_family(body, cb, OCA_KEY_ALGO_CLASSIC);
        if (r != OCA_OK) {
            return r;
        }
        if (ctx->manifest_is_pqc == OCA_SECURE_TRUE) {
            r = commit_revocation_for_family(body, cb, OCA_KEY_ALGO_PQC);
            if (r != OCA_OK) {
                return r;
            }
        }
    }

    /* Security-version OR-in, unless suppressed (bit 0). */
    if ((control & OCA_SECURITY_CONTROL_MSV_UPDATE_DISABLE_BIT) == 0u) {
        if (cb == 0 || cb->get_security_version == 0
            || cb->set_security_version == 0) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        uint8_t device[OCA_LEN_MANIFEST_SECURITY_VERSION];
        if (cb->get_security_version(device) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        const uint8_t *manifest = body + OCA_OFF_MANIFEST_SECURITY_VERSION;
        for (unsigned i = 0u; i < OCA_LEN_MANIFEST_SECURITY_VERSION; ++i) {
            device[i] = (uint8_t)(device[i] | manifest[i]);
        }
        if (cb->set_security_version(device) != OCA_OK) {
            return OCA_FAIL_SECURITY_STATE_UPDATE;
        }
    }

    /* Signature cohort enforcement OR-in, unless suppressed (bit 4). */
    if ((control & OCA_SECURITY_CONTROL_COHORT_ENFORCE_DISABLE_BIT) == 0u) {
        if (cb == 0 || cb->get_signature_cohort_enforce == 0
            || cb->set_signature_cohort_enforce == 0) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        uint8_t device[OCA_LEN_SIGNATURE_COHORT_ENFORCE];
        if (cb->get_signature_cohort_enforce(device) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        const uint8_t *manifest = body + OCA_OFF_SIGNATURE_COHORT_ENFORCE;
        for (unsigned i = 0u; i < OCA_LEN_SIGNATURE_COHORT_ENFORCE; ++i) {
            device[i] = (uint8_t)(device[i] | manifest[i]);
        }
        if (cb->set_signature_cohort_enforce(device) != OCA_OK) {
            return OCA_FAIL_SECURITY_STATE_UPDATE;
        }
    }

    /* Signature class revocation OR-in, unless suppressed (bit 5).
     *
     * The group-code check is repeated here rather than relied upon from the
     * composed validation order. This function is public and burns fuses: a
     * caller may reach it having composed no manifest checks at all, and a
     * fragment of a group code reaching OTP is irreversible. Same reasoning as
     * the deliberately redundant encryption-policy gate in payload.c. */
    if ((control & OCA_SECURITY_CONTROL_CLASS_REVOKE_DISABLE_BIT) == 0u) {
        oca_result_t codes = oca_check_signature_class_group_codes(body);
        if (codes != OCA_OK) {
            return codes;
        }
        if (cb == 0 || cb->get_signature_class_revoke == 0
            || cb->set_signature_class_revoke == 0) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        uint8_t device[OCA_LEN_SIGNATURE_CLASS_REVOKE];
        if (cb->get_signature_class_revoke(device) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        /* The whole field, reserved bytes included. A masked or per-class
         * update would let a group code be assembled a piece at a time, which
         * is exactly what the group-code interlock exists to prevent. */
        const uint8_t *manifest = body + OCA_OFF_SIGNATURE_CLASS_REVOKE;
        for (unsigned i = 0u; i < OCA_LEN_SIGNATURE_CLASS_REVOKE; ++i) {
            device[i] = (uint8_t)(device[i] | manifest[i]);
        }
        if (cb->set_signature_class_revoke(device) != OCA_OK) {
            return OCA_FAIL_SECURITY_STATE_UPDATE;
        }
    }
    return OCA_OK;
}

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

    /* Read as u16: bits 4 and 5 govern the signature posture registers below, so
     * a single-byte load would silently ignore any control bit above 7. */
    uint16_t control = oca_le_u16(body + OCA_OFF_MANIFEST_SECURITY_CONTROL);

    /* ROOT-key revocation OR-in, unless suppressed (bit 1). */
    if ((control & OCA_SECURITY_CONTROL_REVOKE_KEYS_DISABLE_BIT) == 0u) {
        if (cb == 0 || cb->get_root_key_revocation == 0
            || cb->set_root_key_revocation == 0) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        uint8_t device[OCA_LEN_PUBLIC_KEY_CLASSIC_REVOKE];
        if (cb->get_root_key_revocation(OCA_KEY_ALGO_CLASSIC, device) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        const uint8_t *manifest = body + OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE;
        for (unsigned i = 0u; i < OCA_LEN_PUBLIC_KEY_CLASSIC_REVOKE; ++i) {
            device[i] = (uint8_t)(device[i] | manifest[i]);
        }
        if (cb->set_root_key_revocation(OCA_KEY_ALGO_CLASSIC, device) != OCA_OK) {
            return OCA_FAIL_SECURITY_STATE_UPDATE;
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

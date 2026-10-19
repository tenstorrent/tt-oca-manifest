// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief The device's signature posture, applied at boot: algorithm-class
 * revocation and cohort enforcement.
 *
 * Earlier verified manifests OR their signature_class_revoke and
 * signature_cohort_enforce into device state; this is where that state takes
 * effect. The posture fields of the manifest being validated play no part —
 * they govern later boots, once oca_commit_security_state() has folded them in.
 */

#include "oca_validator.h"

#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "secure_boot.h"

/**
 * @brief The signature_class_revoke bit of a classical signature_type.
 *
 * Both RSA-3072 schemes share one class, as do both RSA-4096 schemes; every
 * integrator-defined type shares the integrator class.
 *
 * @param[in] type  The manifest's signature_type_classic byte.
 * @return The bit, or -1 for a type the format does not define.
 */
static int classical_revoke_bit(uint8_t type)
{
    switch (type) {
        case 0x01u: case 0x02u: return 0;   /* RSA-3072 */
        case 0x03u: case 0x04u: return 1;   /* RSA-4096 */
        case 0x05u:             return 2;   /* NIST P-256 ECDSA */
        case 0x06u:             return 3;   /* NIST P-384 ECDSA */
        case 0x07u:             return 4;   /* NIST P-521 ECDSA */
        case 0x0Au:             return 5;   /* Ed25519 */
        case 0x0Bu:             return 6;   /* Ed448 */
        default:                return (type >= 0xF0u) ? 7 : -1;
    }
}

/**
 * @brief The signature_class_revoke bit of a PQC signature_type.
 *
 * The SHA2 and SHAKE parameter sets of each SLH-DSA strength share one class,
 * as do both FN-DSA sizes; every integrator-defined type shares the integrator
 * class.
 *
 * @param[in] type  The manifest's signature_type_pqc byte.
 * @return The bit, or -1 for a type the format does not define.
 */
static int pqc_revoke_bit(uint8_t type)
{
    switch (type) {
        case 0x31u:             return 24;  /* ML-DSA-44 */
        case 0x32u:             return 25;  /* ML-DSA-65 */
        case 0x33u:             return 26;  /* ML-DSA-87 */
        case 0x41u: case 0x42u: return 27;  /* FN-DSA, reserved */
        case 0x51u: case 0x54u: return 28;  /* SLH-DSA-128 */
        case 0x52u: case 0x55u: return 29;  /* SLH-DSA-192 */
        case 0x53u: case 0x56u: return 30;  /* SLH-DSA-256 */
        default:                return (type >= 0xF0u) ? 31 : -1;
    }
}

/**
 * @brief Refuse an enforced class whose algorithm the device has disabled.
 *
 * Disabled either by the class's own bit or, for every class of the group, by
 * the group's intact code. A type that maps to no class is refused rather than
 * passed: the posture cannot vouch for an algorithm it cannot name.
 *
 * @param[in] bit             The class's signature_class_revoke bit, or -1.
 * @param[in] group_disabled  OCA_SECURE_TRUE when the class's whole group is
 *                            disabled by its intact group code.
 * @param[in] revoke          The device's signature_class_revoke state.
 * @retval OCA_OK                               The algorithm is usable.
 * @retval OCA_FAIL_SIGNATURE_ALGORITHM_REVOKED Its class or group is disabled.
 * @retval OCA_FAIL_CRYPTO_FIELD_SIZE           The type names no class.
 */
static oca_result_t check_class_algorithm(int bit, oca_secure_bool_t group_disabled,
                                          const uint8_t revoke[OCA_LEN_SIGNATURE_CLASS_REVOKE])
{
    if (bit < 0) {
        return OCA_FAIL_CRYPTO_FIELD_SIZE;
    }
    oca_secure_bool_t class_disabled =
        (((revoke[bit / 8] >> (bit % 8)) & 1u) != 0u)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    /* FALSE is what lets the algorithm be used, so FALSE is the pattern both
     * words must match; anything else, a corrupted word included, refuses. */
    if (group_disabled == OCA_SECURE_FALSE && class_disabled == OCA_SECURE_FALSE) {
        return OCA_OK;
    }
    return OCA_FAIL_SIGNATURE_ALGORITHM_REVOKED;
}

/**
 * @brief Refuse a cohort the device demands of the ROOT key's signatures that
 *        the manifest does not enforce.
 *
 * A demand is met when the manifest enforces the cohort, and withdrawn when the
 * cohort's whole group is disabled: no algorithm remains that could meet it.
 *
 * @param[in] demanded        OCA_SECURE_TRUE when the device demands the
 *                            cohort.
 * @param[in] enforced        The context's enforcement record for the cohort's
 *                            class.
 * @param[in] group_disabled  OCA_SECURE_TRUE when the cohort's whole group is
 *                            disabled by its intact group code.
 * @retval OCA_OK                             Not demanded, met, or withdrawn.
 * @retval OCA_FAIL_SIGNATURE_COHORT_REQUIRED Demanded and not enforced.
 */
static oca_result_t check_cohort(oca_secure_bool_t demanded,
                                 oca_secure_bool_t enforced,
                                 oca_secure_bool_t group_disabled)
{
    /* Each way to pass is tested against the pattern that selects it, so a
     * corrupted word takes none of them. */
    if (demanded == OCA_SECURE_FALSE
        || enforced == OCA_SECURE_TRUE
        || group_disabled == OCA_SECURE_TRUE) {
        return OCA_OK;
    }
    return OCA_FAIL_SIGNATURE_COHORT_REQUIRED;
}

oca_result_t oca_check_signature_posture(const uint8_t *body,
                                         const oca_callbacks_t *cb,
                                         oca_validation_context_t *ctx)
{
    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    /* Decided afresh by every call: a vouching an earlier check left in the
     * context must not outlive a refusal here. */
    ctx->secure_boot_posture_checked = OCA_SECURE_FALSE;
    if (engaged == OCA_SECURE_FALSE) {
        return OCA_OK;
    }
    if (cb == 0 || cb->get_signature_class_revoke == 0
        || cb->get_signature_cohort_enforce == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    oca_result_t classes = oca_secure_boot_confirm_classes(body, ctx);
    if (classes != OCA_OK) {
        return classes;
    }

    /* Pre-filled with every algorithm disabled and every cohort demanded, so
     * a reader that reports success without writing fails closed. */
    uint8_t revoke[OCA_LEN_SIGNATURE_CLASS_REVOKE];
    uint8_t cohort[OCA_LEN_SIGNATURE_COHORT_ENFORCE];
    for (unsigned i = 0u; i < OCA_LEN_SIGNATURE_CLASS_REVOKE; ++i) {
        revoke[i] = 0xFFu;
    }
    for (unsigned i = 0u; i < OCA_LEN_SIGNATURE_COHORT_ENFORCE; ++i) {
        cohort[i] = 0xFFu;
    }
    if (cb->get_signature_class_revoke(revoke) != OCA_OK
        || cb->get_signature_cohort_enforce(cohort) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    /* A whole group is disabled only by its exact group code; a partially set
     * code byte, which accumulates by OR, disables nothing. Each word is
     * consumed in both directions — FALSE lets an algorithm be used, TRUE
     * withdraws a cohort demand — and each consumer matches only the pattern
     * that permits, so a corrupted word permits neither. */
    const oca_secure_bool_t classical_disabled =
        (revoke[OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE] == OCA_CLASS_REVOKE_CLASSIC_GROUP_CODE)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
    const oca_secure_bool_t pqc_disabled =
        (revoke[OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE] == OCA_CLASS_REVOKE_PQC_GROUP_CODE)
        ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;

    /* Algorithm revocation, for each class the manifest is verified by. */
    if (ctx->secure_boot_enforce_classic == OCA_SECURE_TRUE) {
        oca_result_t r = check_class_algorithm(
            classical_revoke_bit(body[OCA_OFF_SIGNATURE_TYPE]), classical_disabled, revoke);
        if (r != OCA_OK) {
            return r;
        }
    }
    if (ctx->secure_boot_enforce_pqc == OCA_SECURE_TRUE) {
        /* Reads the confirmed variant record, so no PQC offset is read from a
         * body without PQC fields. */
        if (ctx->manifest_is_pqc != OCA_SECURE_TRUE) {
            return OCA_FAIL_SIGNATURE_CLASS_CONTROL;
        }
        oca_result_t r = check_class_algorithm(
            pqc_revoke_bit(body[OCA_PQC_OFF_SIGNATURE_TYPE]), pqc_disabled, revoke);
        if (r != OCA_OK) {
            return r;
        }
    }

    /* Cohort enforcement, for the ROOT key's signatures: the only entity this
     * library verifies. */
    const uint8_t root = (uint8_t)(cohort[0] & OCA_COHORT_ROOT_NIBBLE_MASK);
    oca_result_t met = check_cohort(
        ((root & OCA_COHORT_CLASSICAL_BIT) != 0u) ? OCA_SECURE_TRUE : OCA_SECURE_FALSE,
        ctx->secure_boot_enforce_classic, classical_disabled);
    if (met != OCA_OK) {
        return met;
    }
    met = check_cohort(
        ((root & OCA_COHORT_PQC_BIT) != 0u) ? OCA_SECURE_TRUE : OCA_SECURE_FALSE,
        ctx->secure_boot_enforce_pqc, pqc_disabled);
    if (met != OCA_OK) {
        return met;
    }

    ctx->secure_boot_posture_checked = OCA_SECURE_TRUE;
    return OCA_OK;
}

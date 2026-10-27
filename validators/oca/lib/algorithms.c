// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief The algorithm tables, compiled in by the build configuration.
 */

#include "algorithms.h"

#include "oca_layout.h"
#include "oca_layout_pqc.h"

/* Each table ends in a row whose type is 0x00, a value every class reserves,
 * so a build that enables nothing in a class still has a well-formed table. */

/** @brief Whether an RSA row accepts a DER (PKCS#1) public key in this build. */
#define RSA_PUBLIC_KEY_DER \
    (OCA_CFG_DER_RSA_PUBLIC_KEY ? OCA_DER_ENABLED : OCA_DER_DISABLED)

/** @brief Whether an ECDSA row accepts a DER signature in this build. */
#define ECDSA_SIGNATURE_DER \
    (OCA_CFG_DER_ECDSA_SIGNATURE ? OCA_DER_ENABLED : OCA_DER_DISABLED)

/** The classical signature algorithms this build enables. */
static const oca_signature_algorithm_t CLASSICAL_SIGNATURES[] = {
#if OCA_CFG_SIG_RSA_3072_PKCS1V15_SHA256
    /* Raw key: big-endian modulus (384) || big-endian exponent (4). */
    { 0x01u, 388u, 384u, RSA_PUBLIC_KEY_DER, OCA_DER_UNDEFINED, 0u },
#endif
#if OCA_CFG_SIG_ECDSA_P256_SHA256
    /* Raw key: SEC1 uncompressed point; raw signature: r || s. */
    { 0x05u, 65u, 64u, OCA_DER_UNDEFINED, ECDSA_SIGNATURE_DER, 72u },
#endif
    { 0x00u, 0u, 0u, OCA_DER_UNDEFINED, OCA_DER_UNDEFINED, 0u },
};

/** The PQC signature algorithms this build enables. FIPS 204 and FIPS 205 define
 *  no bare ASN.1 structure for a key or signature, so no PQC row has DER. */
static const oca_signature_algorithm_t PQC_SIGNATURES[] = {
#if OCA_CFG_SIG_ML_DSA_87
    { 0x33u, OCA_PQC_ML_DSA_87_PUBLIC_KEY_BYTES, OCA_PQC_ML_DSA_87_SIGNATURE_BYTES,
      OCA_DER_UNDEFINED, OCA_DER_UNDEFINED, 0u },
#endif
    { 0x00u, 0u, 0u, OCA_DER_UNDEFINED, OCA_DER_UNDEFINED, 0u },
};

/**
 * @brief Whether the format defines a classical signature_type value.
 *
 * Every RSA, ECDSA and EdDSA algorithm the format lists, and the range it
 * leaves to integrators. Anything else is reserved.
 *
 * @param[in] type  The signature_type_classic value.
 * @return Non-zero for an RSA, ECDSA or EdDSA algorithm or an
 *         integrator-defined value; zero for a reserved one.
 */
static int classical_signature_defined(uint8_t type)
{
    return (type >= 0x01u && type <= 0x07u) || type == 0x0Au || type == 0x0Bu
           || type >= 0xF0u;
}

/**
 * @brief Whether the format defines a PQC signature_type value.
 *
 * 0x41 and 0x42 are held for FN-DSA, which FIPS 206 has not yet published, and
 * are reserved until it is.
 *
 * @param[in] type  The signature_type_pqc value.
 * @return Non-zero for an ML-DSA or SLH-DSA algorithm or an integrator-defined
 *         value; zero for a reserved one.
 */
static int pqc_signature_defined(uint8_t type)
{
    return (type >= 0x31u && type <= 0x33u) || (type >= 0x51u && type <= 0x56u)
           || type >= 0xF0u;
}

const oca_signature_algorithm_t *oca_signature_algorithm(oca_key_algorithm_t family,
                                                         uint8_t type,
                                                         oca_result_t *status)
{
    const int pqc = family == OCA_KEY_ALGO_PQC;
    const oca_signature_algorithm_t *row = pqc ? PQC_SIGNATURES : CLASSICAL_SIGNATURES;
    if (type != 0x00u) {
        for (; row->type != 0x00u; ++row) {
            if (row->type == type) {
                *status = OCA_OK;
                return row;
            }
        }
    }
    const int defined = pqc ? pqc_signature_defined(type)
                            : classical_signature_defined(type);
    *status = defined ? OCA_FAIL_ALGORITHM_NOT_ENABLED : OCA_FAIL_ALGORITHM_RESERVED;
    return 0;
}

/** The digests this build enables, for manifest_hash_type and payload_hash_type. */
static const oca_hash_algorithm_t HASHES[] = {
#if OCA_CFG_HASH_SHA2_256
    { 0x01u, 32u },
#endif
    { 0x00u, 0u },
};

const oca_hash_algorithm_t *oca_hash_algorithm(uint8_t type, oca_result_t *status)
{
    if (type != 0x00u) {
        for (const oca_hash_algorithm_t *row = HASHES; row->type != 0x00u; ++row) {
            if (row->type == type) {
                *status = OCA_OK;
                return row;
            }
        }
    }
    /* The SHA2, SHA3 and SHAKE256 digests; the format leaves no range to
     * integrators here. */
    *status = (type >= 0x01u && type <= 0x08u) ? OCA_FAIL_ALGORITHM_NOT_ENABLED
                                               : OCA_FAIL_ALGORITHM_RESERVED;
    return 0;
}

/** The payload ciphers this build enables. */
static const oca_cipher_algorithm_t CIPHERS[] = {
#if OCA_CFG_CIPHER_AES_128_CBC
    { 0x01u, OCA_AES_BLOCK_SIZE },
#endif
#if OCA_CFG_CIPHER_AES_256_CBC
    { 0x02u, OCA_AES_BLOCK_SIZE },
#endif
    { 0x00u, 0u },
};

/**
 * @brief Whether the format defines an encryption_type value.
 *
 * The AES CBC, CBC-HMAC and GCM-SIV modes, the two SM4 modes, and the range
 * left to integrators. 0x13 is explicitly reserved, like every other gap.
 *
 * @param[in] type  The encryption_type value.
 * @return Non-zero for a defined cipher; zero for a reserved value.
 */
static int cipher_defined(uint8_t type)
{
    return (type >= 0x01u && type <= 0x06u) || type == 0x11u || type == 0x12u
           || type >= 0xF0u;
}

const oca_cipher_algorithm_t *oca_cipher_algorithm(uint8_t type, oca_result_t *status)
{
    if (type != 0x00u) {
        for (const oca_cipher_algorithm_t *row = CIPHERS; row->type != 0x00u; ++row) {
            if (row->type == type) {
                *status = OCA_OK;
                return row;
            }
        }
    }
    *status = cipher_defined(type) ? OCA_FAIL_ALGORITHM_NOT_ENABLED
                                   : OCA_FAIL_ALGORITHM_RESERVED;
    return 0;
}

oca_result_t oca_kdf_status(uint16_t kdf)
{
#if OCA_CFG_KDF_SP800_108_HMAC_SHA256
    if (kdf == 0x0001u) {
        return OCA_OK;
    }
#endif
    /* NONE, the SP 800-108r1 HMAC, CMAC and KMAC variants and HKDF, and the
     * range left to integrators. */
    return (kdf <= 0x0008u || kdf >= 0xFF00u) ? OCA_FAIL_ALGORITHM_NOT_ENABLED
                                              : OCA_FAIL_ALGORITHM_RESERVED;
}

oca_result_t oca_key_source_status(unsigned source)
{
#if OCA_CFG_KEY_SOURCE_PRESHARED
    if (source == 0x1u) {
        return OCA_OK;
    }
#endif
    /* The pre-shared secret and the KEM-unwrapped DEK. */
    return (source == 0x1u || source == 0x2u) ? OCA_FAIL_ALGORITHM_NOT_ENABLED
                                              : OCA_FAIL_ALGORITHM_RESERVED;
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief The algorithms this build accepts, and the format's rules for each.
 *
 * Every algorithm the library knows how to judge is a row in a table, and the
 * build configuration decides which rows are compiled in. A manifest value
 * therefore resolves three ways: to a row, to an algorithm the format defines
 * but this build does not enable, or to a value the format reserves.
 *
 * Adding an algorithm means adding its row here, with the sizes the format
 * fixes for it, and marking it implemented in lib/scripts/gen_config.py.
 *
 * This is an internal header — it is not part of the public library API.
 */

#ifndef OCA_ALGORITHMS_H
#define OCA_ALGORITHMS_H

#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Whether a manifest may encode a value as ASN.1 DER.
 *
 * Kept apart from "not enabled" so a manifest that uses DER where the format
 * defines none is a malformed description, while one that uses a DER the
 * build turned off is a portfolio refusal.
 */
typedef enum oca_der_support {
    OCA_DER_UNDEFINED = 0,  /**< The format defines no DER form for this value. */
    OCA_DER_DISABLED  = 1,  /**< Defined, but the build configuration turns it off. */
    OCA_DER_ENABLED   = 2   /**< Defined and accepted. */
} oca_der_support_t;

/**
 * @brief The format's encoding rules for one signature algorithm.
 *
 * Sizes are from the format's encoded-length tables. A DER public key has no
 * fixed size; its declared size is taken as exact. A DER signature's declared
 * size is the algorithm's maximum DER length.
 */
typedef struct oca_signature_algorithm {
    uint8_t           type;               /**< The signature_type_* value. */
    uint16_t          public_key_raw;     /**< Raw public key length. */
    uint16_t          signature_raw;      /**< Raw signature length. */
    oca_der_support_t public_key_der;     /**< Whether a DER public key is accepted. */
    oca_der_support_t signature_der;      /**< Whether a DER signature is accepted. */
    uint16_t          signature_der_max;  /**< Largest DER signature; 0 when undefined. */
} oca_signature_algorithm_t;

/**
 * @brief Resolve a signature_type value against the format and this build.
 *
 * The two classes number their algorithms independently and both reserve
 * 0xF0 and above for integrator-defined algorithms, so the class decides how
 * the value is read.
 *
 * @param[in]  family  Which class's signature_type field the value is from.
 * @param[in]  type    The signature_type value.
 * @param[out] status  Receives OCA_OK, OCA_FAIL_ALGORITHM_NOT_ENABLED or
 *                     OCA_FAIL_ALGORITHM_RESERVED.
 * @return The algorithm's row when this build enables it; NULL when the
 *         format defines it but this build does not enable it, or when the
 *         format reserves the value.
 */
const oca_signature_algorithm_t *oca_signature_algorithm(oca_key_algorithm_t family,
                                                         uint8_t type,
                                                         oca_result_t *status);

/** @brief The largest digest any hash a build can enable produces. */
#define OCA_HASH_MAX_DIGEST_SIZE 32u

/** @brief The format's rules for one digest algorithm. */
typedef struct oca_hash_algorithm {
    uint8_t type;         /**< The manifest_hash_type / payload_hash_type value. */
    uint8_t digest_size;  /**< Digest length in bytes; the leading part of the
                               64-byte hash fields it is stored in. */
} oca_hash_algorithm_t;

/**
 * @brief Resolve a manifest_hash_type or payload_hash_type value.
 *
 * Both fields draw on the same list of digests, and one build configuration
 * section governs both.
 *
 * @param[in]  type    The hash-type value.
 * @param[out] status  Receives OCA_OK, OCA_FAIL_ALGORITHM_NOT_ENABLED or
 *                     OCA_FAIL_ALGORITHM_RESERVED.
 * @return The digest's row when this build enables it; NULL when the format
 *         defines it but this build does not enable it, or reserves the value.
 */
const oca_hash_algorithm_t *oca_hash_algorithm(uint8_t type, oca_result_t *status);

/**
 * @brief The format's rules for one payload cipher.
 *
 * Every cipher a build can enable today is a block mode with PKCS#7 padding,
 * so its ciphertext is a whole number of blocks and runs 1 to block_size bytes
 * longer than the plaintext.
 */
typedef struct oca_cipher_algorithm {
    uint8_t type;        /**< The encryption_type value. */
    uint8_t block_size;  /**< The cipher's block size in bytes. */
} oca_cipher_algorithm_t;

/**
 * @brief Resolve an encryption_type value against the format and this build.
 *
 * Only an encrypted payload names a cipher; 0x00, which a cleartext manifest
 * carries, is reserved here like every other value the format leaves unused.
 *
 * @param[in]  type    The encryption_type value.
 * @param[out] status  Receives OCA_OK, OCA_FAIL_ALGORITHM_NOT_ENABLED or
 *                     OCA_FAIL_ALGORITHM_RESERVED.
 * @return The cipher's row when this build enables it; NULL when the format
 *         defines it but this build does not enable it, or reserves the value.
 */
const oca_cipher_algorithm_t *oca_cipher_algorithm(uint8_t type, oca_result_t *status);

/**
 * @brief Resolve an encryption_key_derivation_function value.
 *
 * The derivation itself is the decryption callback's; this decides only
 * whether the callback may be asked for it.
 *
 * @param[in] kdf  The encryption_key_derivation_function value.
 * @retval OCA_OK                          This build enables it.
 * @retval OCA_FAIL_ALGORITHM_NOT_ENABLED  The format defines it; this build
 *                                         does not enable it.
 * @retval OCA_FAIL_ALGORITHM_RESERVED     The format reserves the value.
 * @return One of the codes above, by how the format and the build treat @p kdf.
 */
oca_result_t oca_kdf_status(uint16_t kdf);

/**
 * @brief Resolve an input_key_source value.
 *
 * The field must select exactly one source, so the empty pattern and every
 * combination of sources are reserved along with the unassigned values.
 *
 * @param[in] source  The three-bit input_key_source value, already shifted
 *                    down from payload_encryption_control.
 * @retval OCA_OK                          This build enables it.
 * @retval OCA_FAIL_ALGORITHM_NOT_ENABLED  The format defines it; this build
 *                                         does not enable it.
 * @retval OCA_FAIL_ALGORITHM_RESERVED     The format reserves the value — every
 *                                         pattern but exactly one source,
 *                                         including none.
 * @return One of the codes above, by how the format and the build treat
 *         @p source.
 */
oca_result_t oca_key_source_status(unsigned source);

#endif /* OCA_ALGORITHMS_H */

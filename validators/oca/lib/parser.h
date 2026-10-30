// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Little-endian field readers, and the one signing-description check,
 *        shared by the structural and crypto checks.
 *
 * The manifest packs its integers little-endian at arbitrary offsets, so every
 * field read goes through one of these rather than a cast: the byte-order
 * convention lives in one place and no alignment is required of the buffer.
 *
 * The structural checks themselves — oca_check_magic(), oca_check_trailer(),
 * oca_check_format_version(), oca_check_reserved_bits() — are declared in
 * oca_validator.h and defined in parser.c.
 */

#ifndef OCA_PARSER_H
#define OCA_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "oca_validator.h"

/**
 * @brief Read a 16-bit little-endian value from a byte buffer.
 *
 * Assembled from explicit byte shifts rather than a cast, so the result does
 * not depend on host endianness and no alignment is required of @p p — the
 * manifest packs fields at arbitrary offsets.
 *
 * @param[in] p  At least 2 readable bytes. Bounds are the caller's to establish.
 * @return The decoded value.
 */
static inline uint16_t oca_le_u16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

/**
 * @brief Read a 32-bit little-endian value from a byte buffer.
 *
 * Host-endian-agnostic and alignment-free, for the same reasons as
 * oca_le_u16().
 *
 * @param[in] p  At least 4 readable bytes. Bounds are the caller's to establish.
 * @return The decoded value.
 */
static inline uint32_t oca_le_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * @brief Read a 64-bit little-endian value from a byte buffer.
 *
 * Composed from two oca_le_u32() reads rather than eight shifts, so the
 * byte-order convention is expressed in exactly one place.
 *
 * @param[in] p  At least 8 readable bytes. Bounds are the caller's to establish.
 * @return The decoded value.
 */
static inline uint64_t oca_le_u64(const uint8_t *p)
{
    return (uint64_t)oca_le_u32(p) | ((uint64_t)oca_le_u32(p + 4) << 32);
}

/**
 * @brief Hold one signature class's signing description to this build.
 *
 * The algorithm and both encodings are resolved against the format and the
 * build's portfolio first, then the declared sizes against the algorithm and
 * the fields, then the padding past them. oca_check_signing_description() runs it for each enforced class, and
 * every check that hands a class's key or signature to a callback runs it
 * again at that point, so neither a skipped description check nor a refusal
 * glitched past puts an algorithm the build leaves off, or a length nothing
 * bounded, in front of a callback.
 *
 * @param[in] body  Whole variant body.
 * @param[in] algo  Which class's description to check.
 * @retval OCA_OK                            The description is consistent.
 * @retval OCA_FAIL_MAGIC                    The body names no known variant.
 * @retval OCA_FAIL_UNSUPPORTED_VARIANT      The body's variant is compiled out.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL  @p algo is the PQC class and the
 *                                           variant carries no PQC fields.
 * @retval OCA_FAIL_ALGORITHM_NOT_ENABLED    The algorithm, an integrator
 *                                           encoding, or a DER encoding it uses
 *                                           is not enabled in this build.
 * @retval OCA_FAIL_ALGORITHM_RESERVED       The signature_type or an encoding
 *                                           is reserved.
 * @retval OCA_FAIL_CRYPTO_FIELD_SIZE        A size or encoding does not fit the
 *                                           algorithm, or padding is not zero.
 * @return The first failing step's result, always one of the codes above.
 */
oca_result_t oca_check_class_description(const uint8_t *body,
                                         oca_key_algorithm_t algo);

#endif /* OCA_PARSER_H */

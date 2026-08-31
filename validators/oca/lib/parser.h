// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Little-endian field readers shared by the structural checks.
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

#endif /* OCA_PARSER_H */

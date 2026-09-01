// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Decode the 16-byte selector_bits region with explicit little-endian
 * shifts (host-endian-agnostic).
 */

#include "selector.h"

#include "oca_layout.h"

/**
 * @brief Read a 32-bit little-endian value from a byte buffer.
 *
 * A file-local copy of the reader in parser.h, kept so this decoder does not
 * pull in that header for one function.
 *
 * @param[in] p  At least 4 readable bytes.
 * @return The decoded value.
 */
static uint32_t le_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * @brief Test one bit of a 32-bit word.
 *
 * Names the bit test so the decoder below reads as a list of what each selector
 * bit means rather than a wall of shifts and masks.
 *
 * @param[in] word         Word to test.
 * @param[in] bit_in_word  Bit index, 0 = least significant. Must be below 32;
 *                         a wider index is undefined behaviour in C, and every
 *                         caller here passes a literal.
 * @return true when the bit is set.
 */
static bool bit_set(uint32_t word, unsigned bit_in_word)
{
    return ((word >> bit_in_word) & 1u) != 0u;
}

void oca_selector_decode(const uint8_t *body, oca_selector_bits_t *out)
{
    const uint8_t *sb = body + OCA_OFF_SELECTOR_BITS;

    /* bits  0..31  → chiplet_id mask */
    out->chiplet_id_mask = le_u32(sb + 0);
    /* bits 32..63  → package_id mask */
    out->package_id_mask = le_u32(sb + 4);
    /* bits 64..95  → system_id mask */
    out->system_id_mask  = le_u32(sb + 8);

    /* bits 96..127 live in the last 4 bytes */
    uint32_t w3 = le_u32(sb + 12);
    out->lifecycle_chiplet_enabled    = bit_set(w3,  0);  /* bit 96 */
    out->lifecycle_package_enabled    = bit_set(w3,  1);  /* bit 97 */
    out->lifecycle_system_enabled     = bit_set(w3,  2);  /* bit 98 */
    out->version_chiplet_min_enabled  = bit_set(w3,  3);  /* bit 99 */
    out->version_chiplet_max_enabled  = bit_set(w3,  4);  /* bit 100 */
    out->version_package_min_enabled  = bit_set(w3,  5);  /* bit 101 */
    out->version_package_max_enabled  = bit_set(w3,  6);  /* bit 102 */
    out->version_system_min_enabled   = bit_set(w3,  7);  /* bit 103 */
    out->version_system_max_enabled   = bit_set(w3,  8);  /* bit 104 */
    /* bits 105..127 of selector_bits are reserved. Decoded for diagnostics
     * only; the Consumer ignores reserved bits (see oca_check_reserved_bits)
     * and does not treat them as an engaged constraint. */
    out->reserved_bits_set =
        ((w3 >> 9) != 0u);  /* high 23 bits of word 3 = bits 105..127 */
}

bool oca_selector_any_constraint_enabled(const oca_selector_bits_t *s)
{
    return s->chiplet_id_mask           != 0u
        || s->package_id_mask           != 0u
        || s->system_id_mask            != 0u
        || s->lifecycle_chiplet_enabled
        || s->lifecycle_package_enabled
        || s->lifecycle_system_enabled
        || s->version_chiplet_min_enabled
        || s->version_chiplet_max_enabled
        || s->version_package_min_enabled
        || s->version_package_max_enabled
        || s->version_system_min_enabled
        || s->version_system_max_enabled;
    /* reserved_bits_set is intentionally excluded: a set reserved bit is not a
     * constraint and must not force identity/lifecycle/version checks to
     * engage (the Consumer ignores reserved bits — see oca_check_reserved_bits). */
}

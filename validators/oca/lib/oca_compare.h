/**
 * @file
 * @brief Fixed-time buffer comparisons.
 *
 * Every byte-buffer comparison in the library goes through one of these. They
 * examine every byte and accumulate the result, so run time is a function of
 * the length alone — never of the contents, and never of how many leading bytes
 * happened to match.
 *
 * Why, given that the most data compared with these function are public?
 *
 *   1. This library compiles freestanding for a boot ROM. An early-exit
 *      comparison is a data-dependent branch: its completion time tells a
 *      fault-injection attacker when to glitch, and the number of matching
 *      bytes is observable through power/EM analysis on silicon. Uniform timing
 *      is standard practice for secure-boot comparisons for that reason alone.
 *   2. oca_identity_compare weighs manifest bytes against values read out of
 *      hardware, and a future CBC-HMAC composite encryption mode (the
 *      AES-*-CBC-HMAC-SHA256 family, rejected by payload.c today) will compare a
 *      SECRET-keyed authentication tag. A keyed-tag comparison with an early
 *      exit is a forgery oracle: it reveals the correct tag one byte at a time.
 *      Routing every comparison through here means that code cannot land with
 *      the wrong primitive by default.
 *
 * C makes no timing guarantees. The `volatile` accumulator stops a compiler from
 * rewriting the fold into an early exit, and the memory access pattern is fixed
 * (all bytes are always read), but this is a best-effort construction in a
 * portable language, not a proof.
 */

#ifndef OCA_COMPARE_H
#define OCA_COMPARE_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compare two buffers in time independent of their contents.
 *
 * Examines every byte and accumulates the differences, so run time is a
 * function of @p len alone — never of how many leading bytes happened to match.
 * The general-purpose comparison every digest check in the library routes
 * through; see the file header for why that matters even for public digests.
 *
 * @param[in] a    First buffer.
 * @param[in] b    Second buffer.
 * @param[in] len  Bytes to compare in each.
 * @return 0 when the buffers are equal over [0, len-1]; non-zero otherwise.
 */
static inline int oca_ct_diff(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t acc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        acc = (uint8_t)(acc | (uint8_t)(a[i] ^ b[i]));
    }
    return acc != 0u;
}

/**
 * @brief Compare only selected byte positions, in content-independent time.
 *
 * Backs the identity checks, where a manifest pins some bytes of a 32-byte
 * identity and leaves the rest free.
 *
 * Unselected bytes are still read and still folded, through a zero mask, so the
 * timing does not reveal WHICH positions were selected — the mask itself is
 * treated as worth protecting, not just the values.
 *
 * @param[in] a          First buffer.
 * @param[in] b          Second buffer.
 * @param[in] len        Bytes to compare. Must be <= 32, the width of
 *                       @p mask_bits.
 * @param[in] mask_bits  Selects participating positions, LSB-first: bit i
 *                       selects byte i.
 * @return 0 when every selected byte over [0, len-1] matches; non-zero otherwise.
 */
static inline int oca_ct_diff_masked(const uint8_t *a, const uint8_t *b,
                                     size_t len, uint32_t mask_bits)
{
    volatile uint8_t acc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        uint32_t selected = (mask_bits >> i) & 1u;
        uint8_t keep = (uint8_t)(0u - selected);   /* 0x00 or 0xFF */
        acc = (uint8_t)(acc | (uint8_t)((uint8_t)(a[i] ^ b[i]) & keep));
    }
    return acc != 0u;
}

/**
 * @brief Test whether any byte of a buffer is non-zero, in fixed time.
 *
 * Used for the "these fields must be zero" invariants, such as the signing
 * fields on a manifest declaring secure_boot = 0. Folds every byte rather than
 * stopping at the first non-zero one, so the position of an offending byte is
 * not observable.
 *
 * @param[in] p    Buffer to test.
 * @param[in] len  Bytes to examine.
 * @return Non-zero when any byte over [0, len-1] is non-zero; 0 when all are zero.
 */
static inline int oca_ct_any_nonzero(const uint8_t *p, size_t len)
{
    volatile uint8_t acc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        acc = (uint8_t)(acc | p[i]);
    }
    return acc != 0u;
}

/**
 * @brief Test whether two bitmaps share any set bit, in fixed time.
 *
 * Backs the ROOT-key revocation check: the selected-key bitmap is intersected
 * with the revoked-key bitmap, and any overlap rejects. Folding rather than
 * short-circuiting means the timing does not reveal which key slot collided.
 *
 * @param[in] a    First bitmap.
 * @param[in] b    Second bitmap.
 * @param[in] len  Bytes to examine in each.
 * @return Non-zero when (a[i] & b[i]) is non-zero for any i in [0, len-1];
 *         0 when the bitmaps are disjoint.
 */
static inline int oca_ct_any_overlap(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t acc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        acc = (uint8_t)(acc | (uint8_t)(a[i] & b[i]));
    }
    return acc != 0u;
}

#endif /* OCA_COMPARE_H */

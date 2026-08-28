/**
 * @file
 * @brief The fault-resistant two-valued type, on its own so callbacks can have
 * it without the rest of the library.
 *
 * Separate from oca_validator.h because two callbacks answer in this type, and
 * the file implementing them is often the one place in an integration that
 * should NOT be pulling in a validator API it does not call — a fuse-read shim,
 * a life-cycle accessor, a board file.
 */

#ifndef OCA_SECURE_BOOL_H
#define OCA_SECURE_BOOL_H

#include <stdint.h>

/**
 * @brief Two-valued state whose "true" is not reachable by corruption.
 *
 * The two values are bitwise complements, so no small-multiplicity bit fault
 * turns one into the other, and zero — a memset, an uninitialized slot, a
 * half-written word — is neither, and resolves to false.
 *
 * A plain unsigned word rather than an enum, deliberately. The purpose of this
 * type is to hold values outside its two defined ones — that is what
 * "corrupted" means — and an enum object holding an unlisted value is what
 * -fsanitize=enum flags and what is undefined behaviour in C++.
 *
 * @warning Test for equality against the pattern that selects the LESS
 *          DEFENSIVE path, so that no corrupted value can reach it. Usually
 *          that is `== OCA_SECURE_TRUE`, because TRUE is what unlocks
 *          something — and `!= OCA_SECURE_FALSE` would then read every
 *          corrupted value as true, inverting the property this type exists to
 *          provide. Where the less defensive path is the one FALSE selects, as
 *          when a recorded "not in force" is what SKIPS a check, the rule
 *          reverses with it: test `== OCA_SECURE_FALSE`, never
 *          `!= OCA_SECURE_TRUE`. The invariant is the direction of the
 *          equality, not the constant on the right of it.
 * @warning Never test one of these for truthiness. OCA_SECURE_FALSE is
 *          0x5A5A5A5A, so `if (x)` and `if (!x)` are both wrong in ways that
 *          compile silently.
 */
typedef uint32_t oca_secure_bool_t;
/** @brief The one bit pattern that means false. Anything else is not false. */
#define OCA_SECURE_FALSE  ((oca_secure_bool_t)0x5A5A5A5Au)
/** @brief The one bit pattern that means true. Test for it by equality. */
#define OCA_SECURE_TRUE   ((oca_secure_bool_t)0xA5A5A5A5u)

#endif /* OCA_SECURE_BOOL_H */

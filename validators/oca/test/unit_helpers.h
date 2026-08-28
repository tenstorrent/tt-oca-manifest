/*
 * unit_helpers.h — Tiny zero-dependency test framework for the OCA
 * validator library. Host-side only.
 *
 * Usage:
 *
 *   #include "unit_helpers.h"
 *
 *   TEST(name_of_test) {
 *       ASSERT_EQ(2 + 2, 4);
 *       ASSERT_TRUE(some_predicate());
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(name_of_test);
 *       return unit_report();
 *   }
 *
 * A test that runs to completion without an ASSERT failing passes. The
 * report prints "<P>/<N> passed" and main returns 0 iff every test
 * passed.
 */

#ifndef OCA_TEST_UNIT_HELPERS_H
#define OCA_TEST_UNIT_HELPERS_H

#include <stdio.h>
#include <string.h>

extern int  g_unit_total;
extern int  g_unit_failed;
extern int  g_unit_current_failed;

#define TEST(name) static void name(void)

/* Clears the shared test fixture. Defined in the test translation unit, which
 * owns the fixture; declared here because the runner calls it.
 *
 * The runner performing the reset is what makes per-case isolation structural
 * rather than a convention each case has to remember: a case cannot observe a
 * value an earlier case set, because there is no reset for a new case to
 * forget. Call it directly only when one case needs fresh state partway
 * through — two validations in a single case, for instance. */
void test_fixture_reset(void);

/* RUN_TEST REGISTERS rather than runs.
 *
 * Deferring execution is what lets the suite run in a different order, which is
 * the only way to demonstrate that no case depends on another having run first.
 * Isolation that is merely intended looks exactly like isolation that holds,
 * right up until a case is deleted and an unrelated one starts failing.
 *
 * The call sites are unchanged — they still read as a list of tests to run. */
typedef void (*unit_test_fn)(void);

#define OCA_UNIT_MAX_TESTS 512

void unit_register(const char *name, unit_test_fn fn);

/* Run every registered test, resetting the fixture before each.
 * `reverse` runs them last-to-first. */
void unit_run_all(int reverse);

#define RUN_TEST(name) unit_register(#name, (name))

#define ASSERT_EQ_INT(actual, expected) do {                           \
        long _a = (long)(actual);                                      \
        long _e = (long)(expected);                                    \
        if (_a != _e) {                                                \
            g_unit_current_failed++;                                   \
            fprintf(stderr, "  %s:%d: %s == %s\n"                      \
                            "    expected: %ld\n"                      \
                            "    actual:   %ld\n",                     \
                    __FILE__, __LINE__, #actual, #expected, _e, _a);   \
        }                                                              \
    } while (0)

#define ASSERT_TRUE(cond) do {                                         \
        if (!(cond)) {                                                 \
            g_unit_current_failed++;                                   \
            fprintf(stderr, "  %s:%d: ASSERT_TRUE(%s) failed\n",       \
                    __FILE__, __LINE__, #cond);                        \
        }                                                              \
    } while (0)

#define ASSERT_MEM_EQ(actual, expected, len) do {                      \
        if (memcmp((actual), (expected), (len)) != 0) {                \
            g_unit_current_failed++;                                   \
            fprintf(stderr, "  %s:%d: ASSERT_MEM_EQ(%s, %s, %zu) failed\n", \
                    __FILE__, __LINE__, #actual, #expected, (size_t)(len)); \
        }                                                              \
    } while (0)

static inline int unit_report(void)
{
    int passed = g_unit_total - g_unit_failed;
    fprintf(stderr, "%d/%d passed\n", passed, g_unit_total);
    return (g_unit_failed == 0) ? 0 : 1;
}

#endif /* OCA_TEST_UNIT_HELPERS_H */

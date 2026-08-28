"""Drift gate: documented result codes match what the functions actually return.

`check_retval_docs.py` is the only check in this project that asks whether a
comment is TRUE rather than well-formed, so it is also the only one whose
failure mode is a documented lie surviving. Both halves matter here: the real
library must be clean, and each of the four rules must be shown still firing
against a synthetic body that breaks exactly one thing.

The fixtures use real OCA_* codes because the checker resolves them against the
library's own enums — a fabricated code would be reported as unknown for the
wrong reason.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "scripts")
RETVAL_CHECKER = os.path.join(SCRIPTS_DIR, "check_retval_docs.py")


def _load(path, name):
    """Import a standalone script by path; it is not on any package path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load(RETVAL_CHECKER, "oca_retval_checker")


def write_source(tmp_path, name, text):
    """Write a synthetic C fixture and return its path."""
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def rules_for(path):
    """Rule names the checker reports for one fixture file."""
    per_file = checker.collect([path])
    enum_members = checker.enum_members_by_type()
    findings = []
    for functions in per_file.values():
        for function in functions:
            checker.check_function(function, findings, enum_members)
    return {finding.rule for finding in findings}


# A helper whose body returns both codes as literals, so the checker can see
# exactly what it produces. Each test below supplies a different @retval set.
ORIGINATING_SOURCE = """\
#include <stdint.h>

/**
 * @brief Originates two codes.
 *
 * A body of nothing but literal returns, which is the only shape the reverse
 * check trusts itself to reason about.
 *
 * @param[in] p  Pointer to inspect.
{retvals}
 */
static oca_result_t fixture_origin(const uint8_t *p)
{{
    if (p == 0) {{
        return OCA_FAIL_INVALID_ARG;
    }}
    return OCA_OK;
}}
"""


def test_real_library_retval_docs_are_accurate():
    """The gate itself: the shipped library must be clean."""
    completed = subprocess.run(
        [sys.executable, RETVAL_CHECKER],
        cwd=PROJECT_ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, (
        "the OCA validator library documents result codes its bodies do not "
        f"match:\n\n{completed.stdout}\n{completed.stderr}")


def test_fully_documented_originator_is_clean(tmp_path):
    """The positive control. If this fails, every negative test below is
    suspect — they differ from it by one broken element each."""
    source = ORIGINATING_SOURCE.format(
        retvals=" * @retval OCA_OK Fine.\n"
                " * @retval OCA_FAIL_INVALID_ARG Null.")
    assert rules_for(write_source(tmp_path, "f.c", source)) == set()


def test_originated_code_without_retval_is_reported(tmp_path):
    """The forward direction: you must document what you yourself produce."""
    source = ORIGINATING_SOURCE.format(retvals=" * @retval OCA_OK Fine.")
    assert "originated-undocumented" in rules_for(write_source(tmp_path, "f.c", source))


def test_retval_the_function_cannot_produce_is_reported(tmp_path):
    """The rule that caught a documented failure code on a no-op function."""
    source = ORIGINATING_SOURCE.format(
        retvals=" * @retval OCA_OK Fine.\n"
                " * @retval OCA_FAIL_INVALID_ARG Null.\n"
                " * @retval OCA_FAIL_MAGIC Never happens here.")
    assert "retval-not-originated" in rules_for(write_source(tmp_path, "f.c", source))


def test_retval_naming_a_nonexistent_code_is_reported(tmp_path):
    source = ORIGINATING_SOURCE.format(
        retvals=" * @retval OCA_OK Fine.\n"
                " * @retval OCA_FAIL_INVALID_ARG Null.\n"
                " * @retval OCA_FAIL_NO_SUCH_CODE Invented.")
    assert "retval-unknown-code" in rules_for(write_source(tmp_path, "f.c", source))


def test_propagating_function_without_return_summary_is_reported(tmp_path):
    """A function that hands back a callee's result owes a @return summary;
    @retval entries alone cannot describe codes it never names."""
    source = """\
#include <stdint.h>
/**
 * @brief Delegates to another check.
 *
 * Everything it can report comes from the function it composes, so the
 * documentation has to say so somewhere.
 *
 * @param[in] p  Pointer to inspect.
 * @retval OCA_OK Fine.
 */
static oca_result_t fixture_delegate(const uint8_t *p)
{
    return some_other_check(p);
}
"""
    assert "propagation-missing-return" in rules_for(write_source(tmp_path, "f.c", source))


def test_propagating_function_with_return_summary_is_clean(tmp_path):
    """False-positive guard, and the reason the reverse check disables itself on
    a propagating body: the codes come from somewhere this analysis cannot see."""
    source = """\
#include <stdint.h>
/**
 * @brief Delegates to another check.
 *
 * Everything it can report comes from the function it composes, which the
 * return summary below states explicitly.
 *
 * @param[in] p  Pointer to inspect.
 * @return The result of the check it delegates to.
 */
static oca_result_t fixture_delegate(const uint8_t *p)
{
    return some_other_check(p);
}
"""
    assert rules_for(write_source(tmp_path, "f.c", source)) == set()


def test_an_undocumented_definition_is_not_this_gate_s_business(tmp_path):
    """A .c definition of a header-declared function carries no block of its
    own — its contract lives in the header. Reporting it here would fight the
    rule that keeps the contract in one place."""
    source = """\
#include <stdint.h>
oca_result_t fixture_check(const uint8_t *body)
{
    return OCA_FAIL_INVALID_ARG;
}
"""
    assert rules_for(write_source(tmp_path, "f.c", source)) == set()

"""Drift gate: the OCA C validator library's doc comments follow house style.

Two responsibilities, deliberately kept in one file:

  1. **Integration.** Run `check_doc_comments.py` over the real library and
     require it clean.

  2. **Unit coverage of the checker itself.** One positive and one negative case
     per rule, driven by synthetic C written to `tmp_path`. The real library
     cannot exercise a negative path — once converted it is correct by
     construction — so the malformed fixtures are generated here rather than the
     cases being skipped.

Why the second half matters as much as the first: a checker that silently
stopped recognising a rule would report a clean library forever and nobody would
notice. Every rule therefore has a test proving it still fires.

This script owns house style only. The rules it used to own that a real C model
does better now belong to `-Wdocumentation` (see the Makefile) and to doxygen
(`test_oca_c_doxygen.py`); result-code accuracy belongs to
`test_oca_c_retval_docs.py`.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

import pytest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "scripts")
DOC_CHECKER = os.path.join(SCRIPTS_DIR, "check_doc_comments.py")


def _load(path, name):
    """Import a standalone script by path; it is not on any package path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load(DOC_CHECKER, "oca_doc_checker")


def write_source(tmp_path, name, text):
    """Write a synthetic C fixture and return its path."""
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def rules_for(path):
    """Rule names the checker reports for one fixture file."""
    findings = []
    checker.check_file(path, findings)
    return {finding.rule for finding in findings}


# A correct block, used as the positive control throughout. Every negative
# fixture below is this with exactly one thing broken, so a test that fails
# points at the rule under test rather than at fixture drift.
GOOD_HEADER = """\
#ifndef FIXTURE_H
#define FIXTURE_H
#include <stdint.h>

/**
 * @brief Check a thing.
 *
 * A longer description that says something the brief does not, such as when
 * this is called and what it guarantees to the caller.
 *
 * @param[in] body  The manifest body to inspect.
 * @retval OCA_OK               Everything checked out.
 * @retval OCA_FAIL_INVALID_ARG The body was NULL.
 */
oca_result_t fixture_check(const uint8_t *body);

#endif
"""


def test_real_library_follows_house_style():
    """The gate itself: the shipped library must be clean."""
    completed = subprocess.run(
        [sys.executable, DOC_CHECKER],
        cwd=PROJECT_ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, (
        "the OCA validator library has doc comments that break house style:"
        f"\n\n{completed.stdout}\n{completed.stderr}")


def test_good_block_raises_nothing(tmp_path):
    """The positive control. If this ever fails, every negative test below is
    suspect — they differ from it by one broken element each."""
    assert rules_for(write_source(tmp_path, "fixture.h", GOOD_HEADER)) == set()


def test_bad_opener_is_reported(tmp_path):
    source = GOOD_HEADER.replace("/**", "/*!", 1)
    assert "bad-opener" in rules_for(write_source(tmp_path, "f.h", source))


def test_missing_brief_is_reported(tmp_path):
    source = GOOD_HEADER.replace(" * @brief Check a thing.\n", "", 1)
    assert "missing-brief" in rules_for(write_source(tmp_path, "f.h", source))


def test_missing_description_is_reported(tmp_path):
    source = GOOD_HEADER.replace(
        " * A longer description that says something the brief does not, such as when\n"
        " * this is called and what it guarantees to the caller.\n *\n", "", 1)
    assert "missing-description" in rules_for(write_source(tmp_path, "f.h", source))


def test_description_that_echoes_the_brief_is_reported(tmp_path):
    """Filler that reoccupies the space a long description should hold.

    Without this rule the no-exemptions requirement invites a reworded title on
    every trivial helper, and each one passes.
    """
    source = GOOD_HEADER.replace(
        " * A longer description that says something the brief does not, such as when\n"
        " * this is called and what it guarantees to the caller.\n",
        " * Check a thing.\n", 1)
    assert "description-echoes-brief" in rules_for(write_source(tmp_path, "f.h", source))


def test_backslash_command_is_reported(tmp_path):
    source = GOOD_HEADER.replace("@brief", "\\brief", 1)
    assert "backslash-command" in rules_for(write_source(tmp_path, "f.h", source))


def test_undirected_param_is_reported(tmp_path):
    source = GOOD_HEADER.replace("@param[in] body", "@param body", 1)
    assert "undirected-param" in rules_for(write_source(tmp_path, "f.h", source))


def test_inline_command_opening_a_description_is_not_a_command(tmp_path):
    """False-positive guard: `@p` is inline markup and routinely opens a prose
    line. Treating it as a section header swallows the description."""
    source = GOOD_HEADER.replace(
        " * A longer description that says something the brief does not, such as when",
        " * @p body is read but never written, which is what this paragraph exists", 1)
    assert "missing-description" not in rules_for(write_source(tmp_path, "f.h", source))


# --------------------------------------------------------------------------
# What the house-style rules deliberately do NOT hold to a contract
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field_comment", [
    "    uint32_t first;   /**< The first field. */",
    "    /** The first field. */\n    uint32_t first;",
    "    /** @brief The first field. */\n    uint32_t first;",
])
def test_a_field_description_is_not_held_to_the_contract_rules(tmp_path, field_comment):
    """A one-line description of a value is not a contract.

    Demanding a brief and a separate long description of `/**< The first
    field. */` produces exactly the filler description-echoes-brief rejects.
    """
    source = f"""\
#ifndef F_H
#define F_H
#include <stdint.h>
/**
 * @brief A thing with a field.
 *
 * Documented so a reader knows what the field means without reading the code
 * that populates it.
 */
typedef struct fixture_thing {{
{field_comment}
}} fixture_thing_t;
#endif
"""
    fired = rules_for(write_source(tmp_path, "f.h", source))
    assert "missing-brief" not in fired
    assert "missing-description" not in fired


def test_a_file_block_needs_no_long_description(tmp_path):
    """For a small translation unit the one-line summary is the whole truth."""
    source = """\
/**
 * @file
 * @brief Variant descriptors and the magic-based resolver.
 */
#include <stdint.h>
"""
    assert rules_for(write_source(tmp_path, "f.c", source)) == set()


def test_a_plain_implementation_comment_is_ignored(tmp_path):
    """`/*` is an implementation note. Whether something needed a doc block and
    lacks one is doxygen's question, not this script's."""
    source = """\
#include <stdint.h>
/* Ordered this way because the cheap test rejects most inputs first. */
oca_result_t fixture_check(const uint8_t *body)
{
    return OCA_OK;
}
"""
    assert rules_for(write_source(tmp_path, "f.c", source)) == set()

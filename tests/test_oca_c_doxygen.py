"""Drift gate: doxygen must report nothing about the OCA validator library.

Doxygen is the entity-discovery half of the documentation gate. It models C
rather than approximating it with regexes and brace depth, so it sees the
shapes a scanner drops — a bare struct, a forward typedef, a macro, a
file-scope variable — and reports each one carrying no documentation. It also
merges a function's declarations, which is how a contract restated in a second
header turns into an error rather than two copies free to drift.

The other two layers: `-Wdocumentation` checks markup against the declaration
it sits on, at compile time on every build (see the Makefile), and
`check_doc_comments.py` owns the house-style rules no tool can know.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OCA_DIR = os.path.join(PROJECT_ROOT, "validators", "oca")

# A header no correct doxygen can object to, shaped to trip the doxygen 1.9.8
# regression: that release reports every documented function in a file
# containing an #include directive as undocumented, so the @file block, the
# include, and the fully @param/@return-documented declaration are each
# load-bearing. Upstream this is
# https://github.com/doxygen/doxygen/issues/11147 -- the undocumented-param
# warnings mis-fire when only XML output is generated, which is how the gate's
# Doxyfile runs; fixed in 1.13.0. 1.9.8 matters because it is what
# `apt install doxygen` gets on current Ubuntu (noble and plucky both package
# it), so it is the version a developer machine is most likely to have.
CANARY_HEADER = """\
/**
 * @file
 * @brief Canary: a fully documented header whose only job is to be accepted.
 */

#ifndef OCA_DOXYGEN_CANARY_H
#define OCA_DOXYGEN_CANARY_H

#include <stdint.h>

/**
 * @brief Add two numbers.
 *
 * @param[in] a  First operand.
 * @param[in] b  Second operand.
 * @return The sum of @p a and @p b.
 */
int32_t oca_canary_add(int32_t a, int32_t b);

#endif
"""


def _skip_unless_doxygen_is_trustworthy(tmp_path):
    """Prove the installed doxygen against the canary before trusting it.

    A gate that fails on correct input is worse than a gate that does not run:
    it teaches people to ignore red. Probing with a known-good header instead
    of comparing version strings means any future release with the same defect
    is caught without maintaining a blocklist, and a patched 1.9.8 would be
    accepted rather than refused on its number.

    The canary run @INCLUDEs the committed Doxyfile just as the real run does,
    so the probe exercises the gate's own warning settings and cannot drift
    from them. The overridden INPUT is absolute, so the Doxyfile's relative
    EXCLUDE entries match nothing -- harmless, since the canary tree contains
    only the canary.

    CI pins doxygen 1.18.0 and asserts the version, so this skip can only fire
    on a developer machine -- there the false failure would otherwise land on
    whoever touches any C file next.
    """
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    (canary_dir / "canary.h").write_text(CANARY_HEADER)
    config = tmp_path / "Doxyfile.canary"
    config.write_text(
        f"@INCLUDE = {os.path.join(OCA_DIR, 'Doxyfile')}\n"
        f"INPUT = {canary_dir}\n"
        f"OUTPUT_DIRECTORY = {tmp_path / 'canary_out'}\n")
    completed = subprocess.run(
        ["doxygen", str(config)],
        cwd=OCA_DIR, capture_output=True, text=True)
    if completed.returncode != 0:
        version = subprocess.run(
            ["doxygen", "--version"],
            capture_output=True, text=True).stdout.strip()
        pytest.skip(
            f"GATE NOT RUN: doxygen {version} rejects a fully documented "
            "canary header, so its warnings cannot distinguish missing "
            "documentation from its own defects. 1.9.8 -- the version apt "
            "installs on current Ubuntu -- flags every documented function in "
            "a file with an #include; install a newer release (CI pins "
            f"1.18.0). Canary output:\n\n{completed.stderr}")


def test_doxygen_reports_no_warnings(tmp_path):
    """Every entity doxygen discovers in lib/ must carry documentation.

    Skipped rather than failed when doxygen is absent, because the suite is
    expected to be green on a machine with no setup. CI installs doxygen and
    asserts it is on PATH, so the gate cannot quietly stop running there — the
    place where it has to hold.

    The run gets its own OUTPUT_DIRECTORY under tmp_path instead of the
    Doxyfile's default. Doxygen creates one directory level, not parents, so
    the committed `build/doxygen` only resolves once something else has made
    `build/` — true on a developer machine that has run make, false on a fresh
    checkout and after `make clean`. There the run failed on the config before
    reading a source file, which is a gate that reports nothing rather than a
    gate that holds. Overriding it here also keeps the check independent of the
    C build tree, which this test never needs.
    """
    if shutil.which("doxygen") is None:
        pytest.skip(
            "GATE NOT RUN: doxygen is not installed, so the entity-discovery "
            "half of the documentation gate did not execute. Install doxygen "
            "to run it locally; CI runs it unconditionally.")

    _skip_unless_doxygen_is_trustworthy(tmp_path)

    # @INCLUDE pulls in the committed config verbatim, so the gate's settings
    # live in one place; the assignment after it wins.
    config = tmp_path / "Doxyfile"
    config.write_text(
        f"@INCLUDE = {os.path.join(OCA_DIR, 'Doxyfile')}\n"
        f"OUTPUT_DIRECTORY = {tmp_path / 'out'}\n")

    # cwd stays OCA_DIR: the Doxyfile's INPUT and EXCLUDE paths are relative
    # to the config's own directory.
    completed = subprocess.run(
        ["doxygen", str(config)],
        cwd=OCA_DIR, capture_output=True, text=True)
    assert completed.returncode == 0, (
        "doxygen found undocumented or contradictory entities in the OCA "
        f"validator library:\n\n{completed.stderr}\n{completed.stdout}")

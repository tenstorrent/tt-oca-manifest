# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The layout headers check their own offsets in every build.

The offsets in the layout headers are copied by hand from the format's field
tables, and each header checks that neighboring fields meet, so a mistyped
digit stops the compile. The library builds -std=c99, so those checks must be
ones C99 runs. A `_Static_assert` is C11, and a C99 build skips it.

Each test plants one mistake in a copy of the library and compiles the file
that holds the check.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import pytest

from oca_fixtures import build_config
from oca_fixtures.toolchain import C_COMPILER

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"
LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
GENERATOR = os.path.join(LIB_DIR, "scripts", "gen_config.py")

# The file holding a check, a #define to change, its new value, and the
# message the check gives.
PLANTED_MISTAKES = [
    pytest.param("oca_layout.h", "OCA_OFF_SIGNATURE_ENCODING", "2094u",
                 "signature_encoding_classic must follow signature_type_classic",
                 id="oca_layout.h"),
    pytest.param("oca_layout_classic.h", "OCA_CLASSIC_OFF_SIGNATURE", "3176u",
                 "signature_classic must begin at the signed-region boundary",
                 id="oca_layout_classic.h"),
    pytest.param("oca_layout_pqc.h", "OCA_PQC_ML_DSA_87_SIGNATURE_BYTES", "29825u",
                 "an ML-DSA-87 signature must fit signature_pqc",
                 id="oca_layout_pqc.h"),
    pytest.param("parser.c", "OCA_MANIFEST_PEEK_MIN", "24u",
                 "peek window must end at manifest_length",
                 id="parser.c"),
]


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


def library_copy(tmp_path):
    """A copy of the library, with the default configuration's header."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    gen = tmp_path / "gen"
    subprocess.run([sys.executable, "-I", GENERATOR, "--config", build_config.DEFAULT_CONFIG,
                    "--out", str(gen / "oca_config.h")],
                   check=True, capture_output=True)
    return lib, gen


def redefine(lib, macro, value):
    """Give one #define in the copy's headers a new value."""
    pattern = re.compile(rf"^(#define {macro}\s+)\w+", re.M)
    changed = 0
    for path in lib.glob("*.h"):
        text, count = pattern.subn(rf"\g<1>{value}", path.read_text())
        if count:
            path.write_text(text)
            changed += count
    assert changed == 1, f"{macro} is not defined exactly once"


def compile_file(lib, gen, name):
    """Compile one file of the library the way the library is built."""
    require_tools(C_COMPILER[0])
    if name.endswith(".h"):
        unit = lib / "probe.c"
        unit.write_text(f'#include "{name}"\nint oca_probe;\n')
    else:
        unit = lib / name
    return subprocess.run(
        [*C_COMPILER, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
         "-fsyntax-only", "-I", str(lib), "-I", str(gen), str(unit)],
        capture_output=True, text=True)


@pytest.mark.parametrize("name, macro, value, message", PLANTED_MISTAKES)
def test_the_unchanged_layout_compiles(tmp_path, name, macro, value, message):
    lib, gen = library_copy(tmp_path)
    result = compile_file(lib, gen, name)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name, macro, value, message", PLANTED_MISTAKES)
def test_a_mistyped_offset_stops_the_compile(tmp_path, name, macro, value, message):
    lib, gen = library_copy(tmp_path)
    redefine(lib, macro, value)
    result = compile_file(lib, gen, name)
    assert result.returncode != 0
    assert message in result.stderr


def test_no_check_in_the_library_needs_c11():
    """A check behind a C11 guard never runs, since every build is C99."""
    found = []
    for name in sorted(os.listdir(LIB_DIR)):
        if name.endswith((".c", ".h")):
            with open(os.path.join(LIB_DIR, name)) as handle:
                text = handle.read()
            if "_Static_assert" in text or "__STDC_VERSION__" in text:
                found.append(name)
    assert found == []

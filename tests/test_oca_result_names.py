# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Every result code has its own name in oca_result_str().

oca_result_t is a fixed-width integer, so a switch over it gets no -Wswitch
check for a missing enumerator, and a code added without a name would print as
"UNKNOWN". These tests compile the library and ask it for the name of every
enumerator the header lists.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import pytest

from oca_fixtures import build_config

LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
GENERATOR = os.path.join(LIB_DIR, "scripts", "gen_config.py")

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"


def result_codes(lib_dir=LIB_DIR) -> list[str]:
    """The enumerators that list the oca_result_t values, in header order."""
    with open(os.path.join(lib_dir, "oca_validator.h")) as handle:
        text = handle.read()
    match = re.search(r"\benum\s+oca_result\s*\{(?P<body>.*?)\}\s*;", text, re.S)
    assert match, "enum oca_result not found in oca_validator.h"
    return re.findall(r"^\s*(OCA_\w+)\s*=", match.group("body"), re.M)


def printed_names(tmp_path, lib_dir=LIB_DIR) -> dict[str, str]:
    """What oca_result_str() returns for every result code, compiled from
    lib_dir."""
    if shutil.which("cc") is None:
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"needs cc ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip("needs cc")
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    subprocess.run([sys.executable, GENERATOR, "--config", build_config.DEFAULT_CONFIG,
                    "--out", str(gen / "oca_config.h")], check=True)
    codes = result_codes(lib_dir)
    probe = tmp_path / "names.c"
    probe.write_text("\n".join(
        ['#include <stdio.h>', '#include "oca_validator.h"', "int main(void)", "{"]
        + [f'    printf("{code} %s\\n", oca_result_str({code}));' for code in codes]
        + ["    return 0;", "}"]) + "\n")
    sources = [os.path.join(lib_dir, name) for name in sorted(os.listdir(lib_dir))
               if name.endswith(".c")]
    binary = tmp_path / "names"
    built = subprocess.run(["cc", "-std=c99", "-Wall", "-Werror", "-I", str(lib_dir),
                            "-I", str(gen), str(probe), *sources, "-o", str(binary)],
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    printed = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    return dict(line.split(" ", 1) for line in printed.stdout.splitlines())


def unnamed_codes(names: dict[str, str]) -> list[str]:
    """Every code whose name is not its enumerator without the OCA_ or
    OCA_FAIL_ prefix."""
    return [code for code, name in names.items()
            if name != re.sub(r"^OCA_(FAIL_)?", "", code)]


def test_every_result_code_prints_its_own_name(tmp_path):
    names = printed_names(tmp_path)
    assert len(names) == len(result_codes()) > 40
    assert unnamed_codes(names) == []


def test_a_code_without_a_name_is_reported(tmp_path):
    """The check is only worth having if it notices a missing case, so one is
    removed from a copy of the library."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    source = lib / "oca_validator.c"
    text = source.read_text()
    case = re.search(r"^ *case OCA_FAIL_MAGIC: .*\n", text, re.M)
    assert case
    source.write_text(text.replace(case.group(0), ""))
    assert unnamed_codes(printed_names(tmp_path, lib)) == ["OCA_FAIL_MAGIC"]

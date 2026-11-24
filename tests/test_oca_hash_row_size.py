# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Every digest site refuses a hash row whose size is not its type's.

The library sizes every digest it takes, compares and chains from its hash
table's row. HASH_DIGEST_SIZE() holds each row within the digest buffers at
compile time, but a row read wrong at run time, by a fault or a corrupted
image, must still be refused where it is used: a short size would compare
only part of each digest, and a zero size none of it.

The unit test test_every_digest_site_holds_the_hash_row_to_its_type checks
each site against whatever SHA2-256 row the build holds. These tests build
the unit tests against a copy of the library whose row is rewritten past
HASH_DIGEST_SIZE() to another size, and require that test to pass there. The
rest of the suite fails against such a row, as it should, and is not judged.
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
SITE_TEST = "test_every_digest_site_holds_the_hash_row_to_its_type"
SHA2_256_ROW = re.compile(r"\{ 0x01u, HASH_DIGEST_SIZE\(32u\) \}")


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


def validator_with_sha2_256_size(tmp_path, size) -> str:
    """A copy of the validator whose SHA2-256 row carries size, unchecked."""
    copy = tmp_path / "oca"
    shutil.copytree(build_config.VALIDATOR_DIR, copy,
                    ignore=shutil.ignore_patterns("build", "__pycache__"))
    table = copy / "lib" / "algorithms.c"
    text, count = SHA2_256_ROW.subn(f"{{ 0x01u, {size}u }}", table.read_text())
    assert count == 1, "the SHA2-256 row of algorithms.c has changed shape"
    table.write_text(text)
    return str(copy)


def site_test_verdict(validator_dir) -> str:
    """The unit-test driver's line for the digest-site test."""
    result = subprocess.run(["make", "-C", validator_dir, "unit_test"],
                            capture_output=True, text=True,
                            env={**os.environ, "PYTHON": sys.executable})
    lines = [line for line in (result.stdout + result.stderr).splitlines()
             if line.endswith(f": {SITE_TEST}")]
    assert len(lines) == 1, result.stdout + result.stderr
    return lines[0]


@pytest.mark.parametrize("size", [0, 1, 31])
def test_every_digest_site_refuses_a_hash_row_of_the_wrong_size(tmp_path, size):
    require_tools("make", C_COMPILER[0], "pkg-config")
    assert site_test_verdict(validator_with_sha2_256_size(tmp_path, size)) \
        == f"PASS: {SITE_TEST}"


def test_the_rewrite_reaches_the_table(tmp_path):
    """The verdict above is only worth having if the copy really holds the
    rewritten row, so the copy's row is read back."""
    copy = validator_with_sha2_256_size(tmp_path, 31)
    with open(os.path.join(copy, "lib", "algorithms.c")) as handle:
        text = handle.read()
    assert "{ 0x01u, 31u }" in text
    assert not SHA2_256_ROW.search(text)

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The validator library's version is the package's.

The library ships inside the package, so a release names one version for both.
The public header states it as OCA_VALIDATOR_VERSION_MAJOR, _MINOR and _PATCH,
and oca_validator_version() reports it; these tests hold those macros to
pyproject.toml and to tt_boot_manifest.__version__, so a version bump that
misses the header fails here.
"""

from __future__ import annotations

import os
import re
import tomllib

import pytest

import tt_boot_manifest
from oca_fixtures import build_config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_HEADER = os.path.join(build_config.VALIDATOR_DIR, "lib", "oca_validator.h")
PARTS = ("MAJOR", "MINOR", "PATCH")


def header_version(text: str) -> str:
    """The version a public header states, as major.minor.patch.

    Raises ValueError unless each part is defined exactly once, as a decimal
    integer.
    """
    parts = []
    for part in PARTS:
        found = re.findall(rf"^#define OCA_VALIDATOR_VERSION_{part} (\d+)u?$", text, re.M)
        if len(found) != 1:
            raise ValueError(f"OCA_VALIDATOR_VERSION_{part} is defined {len(found)} times")
        parts.append(str(int(found[0])))
    return ".".join(parts)


def package_version() -> str:
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def public_header() -> str:
    with open(PUBLIC_HEADER) as handle:
        return handle.read()


def test_the_header_states_the_package_version():
    assert header_version(public_header()) == package_version()


def test_the_package_states_one_version():
    assert tt_boot_manifest.__version__ == package_version()


def test_a_header_with_another_version_is_told_apart():
    """The comparison is only worth having if a header's version is read, not
    assumed."""
    header = public_header()
    bumped = re.sub(r"^(#define OCA_VALIDATOR_VERSION_PATCH )(\d+)", lambda match:
                    f"{match.group(1)}{int(match.group(2)) + 1}", header, flags=re.M)
    assert bumped != header
    assert header_version(bumped) != package_version()


@pytest.mark.parametrize("part", PARTS)
def test_a_header_missing_a_version_part_is_refused(part):
    header = re.sub(rf"^#define OCA_VALIDATOR_VERSION_{part} .*\n", "", public_header(),
                    flags=re.M)
    with pytest.raises(ValueError, match=f"OCA_VALIDATOR_VERSION_{part} is defined 0 times"):
        header_version(header)

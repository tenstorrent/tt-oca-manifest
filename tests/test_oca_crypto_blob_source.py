# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Only the signing-description check builds the blobs a callback receives.

oca_check_class_description() validates a class's algorithm, encodings and
sizes and returns the key and signature blobs from the values it validated.
A caller that built a blob from its own read of the body would hand a callback
whatever the manifest held at that second read, which a fault or another bus
master can have changed since the check. These tests hold every assignment to
a blob's fields to parser.c.
"""

from __future__ import annotations

import os
import re

from oca_fixtures import build_config

LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
DESCRIPTION_SOURCE = "parser.c"

# An assignment to a field only oca_crypto_blob_t has, as a designated
# initializer or through a member or pointer.
BLOB_FIELD_ASSIGNMENT = re.compile(r"(?:\.|->)\s*(?:primitive_type|key_algorithm)\s*=(?!=)")


def blob_assignments(source: str) -> list[int]:
    """The line numbers in source that assign a blob field."""
    return [number for number, line in enumerate(source.splitlines(), start=1)
            if BLOB_FIELD_ASSIGNMENT.search(line)]


def library_blob_builders(lib_dir=LIB_DIR) -> dict[str, list[int]]:
    """Every library source that assigns a blob field, with the lines."""
    found = {}
    for name in sorted(os.listdir(lib_dir)):
        if not name.endswith(".c"):
            continue
        with open(os.path.join(lib_dir, name)) as handle:
            lines = blob_assignments(handle.read())
        if lines:
            found[name] = lines
    return found


def test_only_the_description_check_builds_a_crypto_blob():
    builders = library_blob_builders()
    assert DESCRIPTION_SOURCE in builders
    assert list(builders) == [DESCRIPTION_SOURCE], builders


def test_a_blob_built_elsewhere_is_recognised():
    """The search is only worth having if it matches what it forbids."""
    for line in ("        .primitive_type = body[off_type],",
                 "    .key_algorithm  = algo,",
                 "    blob->primitive_type = type;",
                 "    blobs.public_key.key_algorithm=family;"):
        assert blob_assignments(line) == [1], line
    for line in ("    if (sig->key_algorithm == g_verify_fail_algo) {",
                 "    oca_primitive_type_t primitive_type = 0;",
                 " * the blob's primitive_type names the algorithm"):
        assert blob_assignments(line) == [], line

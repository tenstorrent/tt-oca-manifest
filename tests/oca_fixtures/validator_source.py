# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Read the C validator's source for the gates that pin it to the packer.

Each gate reads what the validator actually accepts rather than trusting a
comment, so it fails when the C and the Python drift apart.
"""

from __future__ import annotations

import os
import re

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
VALIDATOR_PARSER = os.path.join(_PROJECT_ROOT, "validators", "oca", "lib", "parser.c")


def size_check_class_blocks() -> dict[str, str]:
    """The source of each signature class's block in `oca_check_signing_description()`.

    Each block names exactly the primitives and encodings its class admits, and
    every other value falls through to OCA_FAIL_CRYPTO_FIELD_SIZE, so the names
    in a block are its accepted set.
    """
    with open(VALIDATOR_PARSER) as handle:
        text = handle.read()

    match = re.search(
        r"oca_result_t oca_check_signing_description\([^)]*\)\s*"
        r"\{(?P<body>.*?)\n\}\n",
        text,
        re.DOTALL,
    )
    assert match, (
        f"oca_check_signing_description() was not found in {VALIDATOR_PARSER}; if "
        f"it moved or changed shape, update this parser rather than deleting the "
        f"gates that use it")
    body = match.group("body")
    classic_at = body.find("ctx->secure_boot_enforce_classic != OCA_SECURE_FALSE")
    pqc_at = body.find("ctx->secure_boot_enforce_pqc != OCA_SECURE_FALSE")
    assert 0 <= classic_at < pqc_at, (
        "expected a classical class block followed by a PQC class block in "
        "oca_check_signing_description()")
    return {"classic": body[classic_at:pqc_at], "pqc": body[pqc_at:]}

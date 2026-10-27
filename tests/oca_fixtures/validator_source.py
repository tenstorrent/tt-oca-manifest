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
_LIB = os.path.join(_PROJECT_ROOT, "validators", "oca", "lib")
VALIDATOR_PARSER = os.path.join(_LIB, "parser.c")
VALIDATOR_ALGORITHMS = os.path.join(_LIB, "algorithms.c")

_TABLES = {"classic": "CLASSICAL_SIGNATURES", "pqc": "PQC_SIGNATURES"}
_ROW = re.compile(
    r"\{\s*(?P<type>0x[0-9A-Fa-f]+)u,\s*[^,]+,\s*[^,]+,\s*"
    r"(?P<public_key_der>\w+),\s*(?P<signature_der>\w+),")


def signature_table_rows() -> dict[str, list[dict]]:
    """The rows of each signature class's table in algorithms.c.

    Each row is an algorithm the library has rules for, with how it treats DER
    for its public key and signature. The sentinel row that ends each table is
    left out.
    """
    with open(VALIDATOR_ALGORITHMS) as handle:
        text = handle.read()
    rows = {}
    for signature_class, table in _TABLES.items():
        match = re.search(rf"\b{table}\[\]\s*=\s*\{{(?P<body>.*?)\n\}};", text, re.S)
        assert match, (
            f"{table} was not found in {VALIDATOR_ALGORITHMS}; if it moved or "
            f"changed shape, update this parser rather than deleting the gates "
            f"that use it")
        rows[signature_class] = [
            {"type": int(row["type"], 16), "public_key_der": row["public_key_der"],
             "signature_der": row["signature_der"]}
            for row in _ROW.finditer(match.group("body"))
            if int(row["type"], 16) != 0x00
        ]
        assert rows[signature_class], f"{table} has no algorithm rows"
    return rows


def encodings_required_size_accepts() -> set[str]:
    """The encoding enumerators `required_size()` in parser.c admits.

    It names each encoding it accepts and refuses everything else, so the names
    in its body are the accepted set. Whether DER applies to a given value is
    the table row's to say.
    """
    with open(VALIDATOR_PARSER) as handle:
        text = handle.read()
    match = re.search(r"static oca_result_t required_size\([^)]*\)\s*\{(?P<body>.*?)\n\}\n",
                      text, re.S)
    assert match, (
        f"required_size() was not found in {VALIDATOR_PARSER}; if it moved or "
        f"changed shape, update this parser rather than deleting the gates that "
        f"use it")
    return set(re.findall(r"OCA_ENCODING_\w+", match.group("body")))

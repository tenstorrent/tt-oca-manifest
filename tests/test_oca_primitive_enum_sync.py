# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Drift gate: the C validator's `oca_primitive_type_t` must mirror the packer's
signature-type byte values exactly.

`authorization.c`, `crypto_dispatch.c` and `parser.c` cast the manifest's
`signature_type_classic` and `signature_type_pqc` bytes straight to
`oca_primitive_type_t`, and the `verify_signature` callback dispatches on the
result. That is only sound while each enumerator value IS the byte the packer
writes for that algorithm, so this file pins the correspondence in both
directions, as `test_oca_encoding_enum_sync.py` does for `oca_encoding_t`.

The enum also names code points the packer cannot produce. Each of those must be
listed here, so a new enumerator is a deliberate decision rather than a value
the validator starts recognising unnoticed.
"""

from __future__ import annotations

import os
import re

import pytest

from oca_fixtures.validator_source import signature_table_rows
from tt_boot_manifest.oca import constants as oca_consts


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALIDATOR_HEADER = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "oca_validator.h"
)

# `    OCA_PRIMITIVE_ML_DSA_87 = 0x33,  /**< FIPS 204 ML-DSA-87. */`
_ENUMERATOR_RE = re.compile(
    r"^\s*(?P<name>OCA_PRIMITIVE_\w+)\s*=\s*(?P<value>0x[0-9A-Fa-f]+|\d+)\s*,?"
    r"\s*(?:/\*\*<.*\*/)?\s*$"
)

# The byte a bundle carries when its signing fields are unpopulated.
_UNPOPULATED = ("OCA_PRIMITIVE_NONE", 0x00)

# Code points the format defines and the validator names, but this packer never
# writes. Values are pinned so a renumbering is caught here too.
_SPEC_ONLY = {
    "OCA_PRIMITIVE_ML_DSA_44": 0x31,
    "OCA_PRIMITIVE_ML_DSA_65": 0x32,
    "OCA_PRIMITIVE_SLH_DSA_SHA2_128S": 0x51,
    "OCA_PRIMITIVE_SLH_DSA_SHA2_192S": 0x52,
    "OCA_PRIMITIVE_SLH_DSA_SHA2_256S": 0x53,
    "OCA_PRIMITIVE_SLH_DSA_SHAKE_128S": 0x54,
    "OCA_PRIMITIVE_SLH_DSA_SHAKE_192S": 0x55,
    "OCA_PRIMITIVE_SLH_DSA_SHAKE_256S": 0x56,
}


def _oca_primitive_enum_body() -> str:
    """The text between the braces of the `oca_primitive_type_t` typedef."""
    with open(VALIDATOR_HEADER) as handle:
        text = handle.read()

    match = re.search(
        r"typedef\s+enum\s+oca_primitive_type\s*\{(?P<body>.*?)\}\s*oca_primitive_type_t\s*;",
        text,
        re.DOTALL,
    )
    assert match, f"oca_primitive_type_t enum not found in {VALIDATOR_HEADER}"
    return match.group("body")


def _parse_oca_primitive_enum() -> dict[str, int]:
    """Return {enumerator: value} for the `oca_primitive_type_t` enum body."""
    found: dict[str, int] = {}
    for line in _oca_primitive_enum_body().splitlines():
        enumerator = _ENUMERATOR_RE.match(line)
        if enumerator:
            found[enumerator.group("name")] = int(enumerator.group("value"), 0)
    return found


def _packer_primitives() -> dict[str, int]:
    """{expected C enumerator: byte} for every signature type the packer writes."""
    members = list(oca_consts.OcaClassicSignatureType) + list(oca_consts.OcaPqcSignatureType)
    expected = {f"OCA_PRIMITIVE_{member.name}": member.value for member in members}
    expected[_UNPOPULATED[0]] = _UNPOPULATED[1]
    return expected


def test_enum_parser_reads_every_enumerator_line():
    """The regex must not silently skip an enumerator, or the reverse-direction
    test below would pass against a header it never fully read."""
    declared = re.findall(r"^\s*(OCA_PRIMITIVE_\w+)\s*=", _oca_primitive_enum_body(),
                          re.MULTILINE)

    assert sorted(declared) == sorted(_parse_oca_primitive_enum())


def test_every_value_the_packer_can_write_has_its_enumerator():
    """Each signature type the packer emits is named by the C enum, under the
    matching name and with the same byte value."""
    c_enum = _parse_oca_primitive_enum()
    for c_name, byte in _packer_primitives().items():
        assert c_name in c_enum, (
            f"the packer can write signature type {byte:#04x} but "
            f"oca_primitive_type_t has no {c_name}")
        assert c_enum[c_name] == byte, (
            f"{c_name} = {c_enum[c_name]:#04x} in oca_validator.h but the packer "
            f"writes {byte:#04x}; the validator casts the byte straight to the enum")


def test_every_other_enumerator_is_a_listed_spec_code_point():
    """An enumerator the packer cannot write is either a format code point
    listed in _SPEC_ONLY with its pinned value, or a mistake."""
    packer = _packer_primitives()
    for c_name, c_value in _parse_oca_primitive_enum().items():
        if c_name in packer:
            continue
        assert c_name in _SPEC_ONLY, (
            f"{c_name} = {c_value:#04x} is in oca_primitive_type_t but the packer "
            f"cannot write it and it is not listed in _SPEC_ONLY")
        assert c_value == _SPEC_ONLY[c_name], (
            f"{c_name} = {c_value:#04x} in oca_validator.h, pinned here as "
            f"{_SPEC_ONLY[c_name]:#04x}")


def test_spec_only_list_names_no_value_the_packer_writes():
    """A code point the packer gains support for leaves _SPEC_ONLY, so the list
    never claims a supported algorithm is unsupported."""
    packer_values = set(_packer_primitives().values())
    overlap = {name for name, value in _SPEC_ONLY.items() if value in packer_values}
    assert not overlap, f"_SPEC_ONLY lists values the packer writes: {sorted(overlap)}"


def _c_accepted_primitives_by_class() -> dict[str, set[int]]:
    """The signature_type values the library has algorithm rows for, per class."""
    return {signature_class: {row["type"] for row in rows}
            for signature_class, rows in signature_table_rows().items()}


@pytest.mark.parametrize("signature_class,packer_enum", [
    ("classic", oca_consts.OcaClassicSignatureType),
    ("pqc", oca_consts.OcaPqcSignatureType),
])
def test_validator_accepts_exactly_the_primitives_the_packer_writes(
        signature_class, packer_enum):
    """For each signature class, the algorithms the validator has rows for equal
    the ones the packer can write: a primitive the packer signs with but the
    validator refuses, or one the validator admits that no producer makes, is a
    silent divergence either way. Each row's value must also be an enumerator
    of oca_primitive_type_t, which the blob hands to the verify callback."""
    c_enum = _parse_oca_primitive_enum()
    accepted = _c_accepted_primitives_by_class()[signature_class]
    assert accepted <= set(c_enum.values()), "a table row has no oca_primitive_type_t enumerator"
    packer = {member.value for member in packer_enum}
    assert accepted == packer, (
        f"{signature_class}: the validator accepts "
        f"{sorted(hex(v) for v in accepted)} but the packer writes "
        f"{sorted(hex(v) for v in packer)}")

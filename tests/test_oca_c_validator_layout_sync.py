# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Drift-check between validators/oca/lib/oca_layout.h and src/oca/constants.py.

Any offset, length, or mask the C validator depends on must match the Python
packer byte-for-byte. The check lives in pytest so it runs alongside the rest
of the suite and gates `pytest -m "not aws"`.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNC_SCRIPT = os.path.join(
    PROJECT_ROOT,
    "validators", "oca", "lib", "scripts", "sync_layout.py",
)
PQC_HEADER = os.path.join(
    PROJECT_ROOT,
    "validators", "oca", "lib", "oca_layout_pqc.h",
)

_DEFINE_RE = re.compile(r"^\s*#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)u?")


def _parse_defines(path: str) -> dict[str, int]:
    out: dict[str, int] = {}
    with open(path) as f:
        for line in f:
            m = _DEFINE_RE.match(line)
            if m:
                out[m.group(1)] = int(m.group(2), 0)
    return out


def test_oca_c_layout_in_sync_with_python_constants():
    result = subprocess.run(
        [sys.executable, SYNC_SCRIPT],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            "oca_layout.h has drifted from src/oca/constants.py.\n"
            f"stderr:\n{result.stderr}\n"
            f"stdout:\n{result.stdout}\n"
            "Run `python validators/oca/lib/scripts/sync_layout.py "
            "--suggest-fix` for a sed remediation snippet."
        )


def _load_sync_layout():
    import importlib.util

    spec = importlib.util.spec_from_file_location("oca_sync_layout", SYNC_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sync_passes(monkeypatch, extra_mapping: dict) -> bool:
    """Run the drift gate in process with `extra_mapping` added to MAPPING."""
    sync_layout = _load_sync_layout()
    monkeypatch.setattr(sync_layout, "MAPPING", {**sync_layout.MAPPING, **extra_mapping})
    monkeypatch.setattr(sys, "argv", [SYNC_SCRIPT])
    return sync_layout.main() == 0


def test_sync_gate_pins_a_c_value_to_an_enum_member(monkeypatch):
    """`EnumName.MEMBER` resolves to the member's value, so a C value whose
    only Python form is an enum member is compared, not skipped."""
    from tt_boot_manifest.oca import constants as oca_consts

    sync_layout = _load_sync_layout()
    assert sync_layout.python_value(oca_consts, "OcaClassicHashType.SHA2_256") == 0x01
    assert sync_layout.python_value(oca_consts, "OFF_MANIFEST_HASH_TYPE") == 2067
    # The pairing exercises the resolution only: any C layout value equal to the
    # member's passes, and one that differs fails.
    assert _sync_passes(monkeypatch, {
        "OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT": ("OcaClassicHashType.SHA2_256", "hex")})
    assert not _sync_passes(monkeypatch, {
        "OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT":
            ("OcaClassicSignatureType.ECDSA_P256_SHA256", "hex")})


@pytest.mark.parametrize("py_name", ["NO_SUCH_CONSTANT", "OcaClassicHashType.NO_SUCH_MEMBER"])
def test_sync_gate_fails_a_mapping_whose_python_side_names_nothing(monkeypatch, py_name):
    """A misspelt counterpart would otherwise compare nothing and pass."""
    sync_layout = _load_sync_layout()
    assert sync_layout.python_value(sync_layout, py_name) is None
    assert not _sync_passes(monkeypatch, {"OCA_OFF_MAGIC": (py_name, "dec")})


# oca_layout_pqc.h define -> its counterpart in tt_boot_manifest.oca.constants.
_PQC_FIELDS = (
    ("OCA_PQC_BODY_SIZE",                  "OCA_PQC_BODY_SIZE"),
    ("OCA_PQC_SIGNED_REGION_END",          "PQC_SIGNED_REGION_END"),
    ("OCA_PQC_OFF_CLASSIC_TRAILER_SLOT",   "OFF_CLASSIC_MANIFEST_TRAILER"),
    ("OCA_PQC_OFF_SIGNATURE_TYPE",         "OFF_SIGNATURE_TYPE_PQC"),
    ("OCA_PQC_OFF_SIGNATURE_ENCODING",     "OFF_SIGNATURE_ENCODING_PQC"),
    ("OCA_PQC_OFF_SIGNATURE_SIZE",         "OFF_SIGNATURE_SIZE_PQC"),
    ("OCA_PQC_OFF_PUBLIC_KEY_SELECT",      "OFF_PUBLIC_KEY_SELECT_PQC"),
    ("OCA_PQC_LEN_PUBLIC_KEY_SELECT",      "LEN_PUBLIC_KEY_SELECT_PQC"),
    ("OCA_PQC_OFF_PUBLIC_KEY",             "OFF_PUBLIC_KEY_PQC"),
    ("OCA_PQC_LEN_PUBLIC_KEY",             "LEN_PUBLIC_KEY_PQC"),
    ("OCA_PQC_OFF_PUBLIC_KEY_ENCODING",    "OFF_PUBLIC_KEY_ENCODING_PQC"),
    ("OCA_PQC_OFF_PUBLIC_KEY_SIZE",        "OFF_PUBLIC_KEY_SIZE_PQC"),
    ("OCA_PQC_OFF_PUBLIC_KEY_REVOKE",      "OFF_PUBLIC_KEY_PQC_REVOKE"),
    ("OCA_PQC_LEN_PUBLIC_KEY_REVOKE",      "LEN_PUBLIC_KEY_PQC_REVOKE"),
    ("OCA_PQC_OFF_TRAILER",                "OFF_PQC_MANIFEST_TRAILER"),
    ("OCA_PQC_OFF_SIGNATURE",              "OFF_PQC_SIGNATURE_CLASSIC"),
    ("OCA_PQC_OFF_MANIFEST_HASH",          "OFF_PQC_MANIFEST_HASH"),
    ("OCA_PQC_OFF_PAYLOAD_OFFSET",         "OFF_PQC_PAYLOAD_OFFSET"),
    ("OCA_PQC_OFF_SIGNATURE_PQC",          "OFF_SIGNATURE_PQC"),
    ("OCA_PQC_LEN_SIGNATURE_PQC",          "LEN_SIGNATURE_PQC"),
    ("OCA_PQC_ML_DSA_87_PUBLIC_KEY_BYTES", "ML_DSA_87_PUBLIC_KEY_BYTES"),
    ("OCA_PQC_ML_DSA_87_SIGNATURE_BYTES",  "ML_DSA_87_SIGNATURE_BYTES"),
)


@pytest.mark.parametrize("c_name,py_name", _PQC_FIELDS)
def test_pqc_layout_field_matches_python_constant(c_name, py_name):
    """Every oca_layout_pqc.h field matches the packer's constant byte for byte,
    independently of the sync script, so a broken script cannot hide drift in
    the variant whose fields the validator reads to verify a PQC signature."""
    from tt_boot_manifest.oca import constants as oca_consts

    c_defines = _parse_defines(PQC_HEADER)
    assert c_name in c_defines, f"{c_name} missing from oca_layout_pqc.h"
    py_value = getattr(oca_consts, py_name)
    assert c_defines[c_name] == py_value, (
        f"{c_name}={c_defines[c_name]} in oca_layout_pqc.h but "
        f"src/oca/constants.py {py_name}={py_value}"
    )


def test_pqc_signed_fields_tile_the_pqc_crypto_block():
    """The PQC-only signed fields sit back to back from the end of the 0x35
    slot to the pqc_manifest_trailer, and the trailer closes the signed region:
    no gap or overlap a field offset could drift into unnoticed."""
    from tt_boot_manifest.oca import constants as oca_consts

    fields = (
        (oca_consts.OFF_SIGNATURE_TYPE_PQC, 1),
        (oca_consts.OFF_SIGNATURE_ENCODING_PQC, 1),
        (oca_consts.OFF_SIGNATURE_SIZE_PQC, 2),
        (oca_consts.OFF_PUBLIC_KEY_SELECT_PQC, oca_consts.LEN_PUBLIC_KEY_SELECT_PQC),
        (oca_consts.OFF_PUBLIC_KEY_PQC, oca_consts.LEN_PUBLIC_KEY_PQC),
        (oca_consts.OFF_PUBLIC_KEY_ENCODING_PQC, 1),
        (oca_consts.OFF_PUBLIC_KEY_SIZE_PQC, 2),
        (oca_consts.OFF_PUBLIC_KEY_PQC_REVOKE, oca_consts.LEN_PUBLIC_KEY_PQC_REVOKE),
        (oca_consts.OFF_RESERVED_PQC, oca_consts.LEN_RESERVED_PQC),
    )
    expected = oca_consts.OFF_CLASSIC_MANIFEST_TRAILER + len(oca_consts.PQC_CLASSIC_TRAILER_FILL)
    for offset, length in fields:
        assert offset == expected, f"PQC field at {offset}, expected {expected}"
        expected += length
    assert expected == oca_consts.OFF_PQC_MANIFEST_TRAILER
    assert (oca_consts.OFF_PQC_MANIFEST_TRAILER + len(oca_consts.PQC_TRAILER)
            == oca_consts.PQC_SIGNED_REGION_END == oca_consts.OFF_PQC_SIGNATURE_CLASSIC)


def test_ml_dsa_87_encodings_fit_their_fields():
    """A raw ML-DSA-87 key and signature fit the PQC fields that carry them,
    and their lengths fit the u16 size fields. The C header asserts the same
    only under C11, which the -std=c99 library build never compiles."""
    from tt_boot_manifest.oca import constants as oca_consts

    assert oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES <= oca_consts.LEN_PUBLIC_KEY_PQC
    assert oca_consts.ML_DSA_87_SIGNATURE_BYTES <= oca_consts.LEN_SIGNATURE_PQC
    assert max(oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES,
               oca_consts.ML_DSA_87_SIGNATURE_BYTES) < (1 << 16)

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


def test_pqc_layout_anchors_match_python_constants():
    """Explicit, script-independent guard: the PQC anchor values the Python
    packer names must match oca_layout_pqc.h byte-for-byte. The per-field PQC
    offsets are derived from region sizes on the Python side and asserted
    internally in the C header, so only these independently-named anchors are
    diffable across the two producers."""
    from tt_boot_manifest.oca import constants as oca_consts

    c_defines = _parse_defines(PQC_HEADER)
    anchors = [
        ("OCA_PQC_BODY_SIZE",          oca_consts.OCA_PQC_BODY_SIZE),
        ("OCA_PQC_SIGNED_REGION_END",  oca_consts.PQC_SIGNED_REGION_END),
        ("OCA_PQC_OFF_PAYLOAD_OFFSET", oca_consts.PQC_PAYLOAD_OFFSET_FIELD),
        ("OCA_PQC_LEN_SIGNATURE_PQC",  oca_consts.PQC_SIGNATURE_SIZE),
    ]
    for c_name, py_value in anchors:
        assert c_name in c_defines, f"{c_name} missing from oca_layout_pqc.h"
        assert c_defines[c_name] == py_value, (
            f"{c_name}={c_defines[c_name]} in oca_layout_pqc.h but "
            f"src/oca/constants.py has {py_value}"
        )

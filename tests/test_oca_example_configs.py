# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Pure-Python build-and-validate coverage for the shipped example configs.

Each `configs/oca_*.yaml` example is packed in-process by the Python producer and
its manifest output is validated WITHOUT the C validator or any C toolchain:
structural framing, `manifest_hash` recomputation, and — for secure-boot
manifests — signature verification against the embedded public key via
`cryptography`. This complements the subprocess-driven C end-to-end integration
test (`test_oca_c_validator_integration.py`) and runs in a plain Python
environment.

Device-state policy checks (ROOT-key revocation, anti-rollback) depend on device
state and are the C validator's job; here we assert the manifest *output* is
well-formed, authentic, and carries the device-state field values the example
config declares.
"""

from __future__ import annotations

import hashlib
import os
import struct

import pytest
from oca_fixtures.manifest_reader import verify_classic_signature
from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.utils import load_config

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Classic examples validated end-to-end in-process (magic, framing, hash, and
# signature when secure boot is enabled).
CLASSIC_EXAMPLES = [
    "configs/oca_classic_example.yaml",
    "configs/oca_classic_control_plane_example.yaml",
    "configs/oca_encrypted_example.yaml",
    "configs/oca_secure_boot_device_state_example.yaml",
]


def _pack(cfg_rel, tmp_path):
    """Load a repo-relative example config and pack it in-process.

    Payload image paths are redirected to a freshly-created file so the test
    does not depend on the examples' gitignored placeholder images; the tracked
    dev signing keys the examples reference are resolved against the repo root.
    """
    cfg = load_config(os.path.join(PROJECT_ROOT, cfg_rel))
    img = tmp_path / "img.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF\x90\x90\x90\x90")
    for entry in cfg.get("payload_images", []):
        entry["path"] = str(img)
    prev = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        return pack_oca_bundle(cfg)
    finally:
        os.chdir(prev)


def _u128(body, off):
    """Read a 16-byte little-endian bitmap/flag field at `off`."""
    return int.from_bytes(body[off:off + 16], "little")




def _validate_classic_manifest(bundle):
    """Pure-Python validation of a Classic OCA manifest's output."""
    assert len(bundle) >= oca_consts.OCA_CLASSIC_BODY_SIZE
    body = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    assert body[0:4] == b"OCAC", "classic magic"
    assert struct.unpack_from("<I", body, oca_consts.OFF_MANIFEST_LENGTH)[0] \
        == oca_consts.OCA_CLASSIC_BODY_SIZE, "manifest_length field"
    assert body[oca_consts.OFF_CLASSIC_MANIFEST_TRAILER:
                oca_consts.OFF_CLASSIC_MANIFEST_TRAILER + 4] == b"\xCA" * 4, "trailer"

    # manifest_hash must recompute over the signed region.
    signed = body[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]
    embedded = body[oca_consts.OFF_MANIFEST_HASH:
                    oca_consts.OFF_MANIFEST_HASH + oca_consts.MANIFEST_HASH_DIGEST_SIZE]
    assert embedded == hashlib.sha256(signed).digest(), "manifest_hash recompute"

    # When the manifest declares secure boot, the embedded signature must verify
    # against the embedded public key.
    if body[oca_consts.OFF_SECURE_BOOT_CONTROL] & 0x01:
        verify_classic_signature(body, signed)


@pytest.mark.parametrize("cfg", CLASSIC_EXAMPLES)
def test_classic_example_builds_and_validates(cfg, tmp_path):
    """Every classic example config packs and produces a manifest that passes
    pure-Python structural + hash + signature validation."""
    _validate_classic_manifest(_pack(cfg, tmp_path))


def test_pqc_example_builds_structurally(tmp_path):
    """The PQC example packs into a structurally-correct OCAP manifest. (PQC
    signature verification is a deferred capability, so only framing is checked
    here.)"""
    bundle = _pack("configs/oca_pqc_example.yaml", tmp_path)
    assert len(bundle) >= oca_consts.OCA_PQC_BODY_SIZE
    body = bundle[: oca_consts.OCA_PQC_BODY_SIZE]
    assert body[0:4] == b"OCAP", "pqc magic"
    assert struct.unpack_from("<I", body, oca_consts.OFF_MANIFEST_LENGTH)[0] \
        == oca_consts.OCA_PQC_BODY_SIZE, "manifest_length field"


def test_secure_boot_device_state_example_fields(tmp_path):
    """The device-state secure-boot example carries the device-state field values
    it documents, and does not revoke the ROOT key it selects."""
    body = _pack("configs/oca_secure_boot_device_state_example.yaml",
                 tmp_path)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    assert struct.unpack_from(
        "<H", body, oca_consts.OFF_MANIFEST_SECURITY_CONTROL)[0] == 0x00
    assert _u128(body, oca_consts.OFF_MANIFEST_SECURITY_VERSION) == 0x07
    select = _u128(body, oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC)
    revoke = _u128(body, oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE)
    assert select == 0x01
    assert revoke == 0x06

    # The signature posture registers the example documents: demand a classical
    # ROOT signature, revoke nothing.
    assert struct.unpack_from(
        "<Q", body, oca_consts.OFF_SIGNATURE_COHORT_ENFORCE)[0] == 0x01
    assert struct.unpack_from(
        "<Q", body, oca_consts.OFF_SIGNATURE_CLASS_REVOKE)[0] == 0x00
    # The selected ROOT key must not be in the revoke set — the property the
    # validator enforces before using a key, checked here on the config output.
    assert select & revoke == 0

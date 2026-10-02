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

The `examples/oca_classic_basic` walkthrough is covered too: its README's
signed-bundle step is applied to its config as written and the result checked
with the example's own `verify.py`.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import struct
import textwrap

import pytest
from cryptography.exceptions import InvalidSignature
from oca_fixtures.manifest_reader import verify_classic_signature
from tt_boot_manifest.key_hygiene import ALLOW_CONFIG_FIELD, ALLOW_ENV_VAR, KeyHygieneError
from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.utils import load_config

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASIC_EXAMPLE_DIR = os.path.join(PROJECT_ROOT, "examples", "oca_classic_basic")
SIGNED_STEP_HEADING = "## Switching to a signed bundle"
UNSIGNED_LINE = "secure_boot: 0"

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


# ---------------------------------------------------------------------------
# examples/oca_classic_basic: the README's signed-bundle step
#
# conftest.py sets the development-key override and $ROOT for the whole
# session. A reader following the README in a bare clone has neither, so both
# are removed here; otherwise the step passes for a reason the reader lacks.
# ---------------------------------------------------------------------------


def _readme_signed_snippet():
    """The YAML block the README's signed-bundle step substitutes into config.yaml."""
    with open(os.path.join(BASIC_EXAMPLE_DIR, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    assert SIGNED_STEP_HEADING in readme, f"README.md lost its {SIGNED_STEP_HEADING!r} section"
    section = readme.split(SIGNED_STEP_HEADING, 1)[1]
    assert "```yaml" in section, f"no YAML block under {SIGNED_STEP_HEADING!r}"
    return textwrap.dedent(section.split("```yaml", 1)[1].split("```", 1)[0]).strip()


def _apply_signed_step(snippet):
    """config.yaml with its `secure_boot: 0` line replaced by `snippet`."""
    with open(os.path.join(BASIC_EXAMPLE_DIR, "config.yaml"), encoding="utf-8") as f:
        lines = f.read().splitlines()
    assert lines.count(UNSIGNED_LINE) == 1, \
        f"config.yaml needs exactly one {UNSIGNED_LINE!r} line for the README step to replace"
    at = lines.index(UNSIGNED_LINE)
    lines[at:at + 1] = snippet.splitlines()
    return "\n".join(lines) + "\n"


def _pack_signed_step(tmp_path, monkeypatch, snippet):
    """Pack config.yaml after the signed-bundle step, as a bare clone would."""
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    monkeypatch.delenv("ROOT", raising=False)
    monkeypatch.chdir(PROJECT_ROOT)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(_apply_signed_step(snippet), encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg is not None, "config.yaml does not parse after the README step"
    return pack_oca_bundle(cfg)


def _load_example_verifier():
    """Import examples/oca_classic_basic/verify.py, which is not a package module."""
    spec = importlib.util.spec_from_file_location(
        "oca_classic_basic_verify", os.path.join(BASIC_EXAMPLE_DIR, "verify.py"))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def _example_signature_verifies(verifier, bundle):
    """Whether the example's own verify_signature() accepts `bundle`."""
    try:
        verifier.verify_signature(bundle)
    except InvalidSignature:
        return False
    return True


def test_basic_example_signed_step_builds_and_verifies(tmp_path, monkeypatch):
    """The README's signed-bundle step, applied as written, packs a bundle that
    passes the example's verify.py, and a tampered copy fails it."""
    bundle = _pack_signed_step(tmp_path, monkeypatch, _readme_signed_snippet())
    verifier = _load_example_verifier()

    verifier.verify_unsigned(bundle)
    assert _example_signature_verifies(verifier, bundle)

    tampered = bytearray(bundle)
    tampered[oca_consts.OFF_MANIFEST_IDENTIFIER] ^= 0x01
    assert not _example_signature_verifies(verifier, bytes(tampered))


def test_basic_example_signed_step_needs_test_key_opt_in(tmp_path, monkeypatch):
    """Without its `allow_test_signing_key` line the same step is refused.

    This is the control for the test above: the guard is live under this setup,
    so that test passes because the README declares the development key.
    """
    snippet = "\n".join(
        line for line in _readme_signed_snippet().splitlines()
        if not line.startswith(f"{ALLOW_CONFIG_FIELD}:"))

    with pytest.raises(KeyHygieneError):
        _pack_signed_step(tmp_path, monkeypatch, snippet)

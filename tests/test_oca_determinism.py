# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Determinism and byte-stability guards for the OCA-classic packer.

The signed region embeds a SHA-256 over manifest bytes, so any non-determinism
silently breaks reproducible builds. These tests pin every variable input
(timestamp) and assert two back-to-back runs yield the same bytes — for the
canonical example configs and for the ergonomic-vs-raw selector_bits modes.
"""

from __future__ import annotations

import hashlib
import os
from copy import deepcopy

import pytest

from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.utils import load_config


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_paths(cfg, base_dir):
    """Make payload-image paths absolute so packer can locate the binaries
    regardless of the test runner's CWD."""
    for img in cfg.get("payload_images", []):
        if not os.path.isabs(img["path"]):
            img["path"] = os.path.join(base_dir, img["path"])
    return cfg


# ---------------------------------------------------------------------------
# OCA-classic determinism with an explicit timestamp.
# ---------------------------------------------------------------------------


@pytest.fixture
def oca_repro_config(tmp_path):
    """Smallest deterministic OCA-classic config — explicit timestamp pins
    every non-deterministic input."""
    img_path = tmp_path / "img1.bin"
    img_path.write_bytes(b"\xDE\xAD\xBE\xEF" * 4)  # 16 bytes
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "REPRO1",
        "description": "OCA-classic determinism smoke test",
        "secure_boot": 0,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [
            {"type": "REPRO1XXBLSTAGE1", "path": str(img_path)},
        ],
    }


def test_oca_classic_byte_identical_repeated_runs(oca_repro_config):
    """Two back-to-back OCA-classic runs against the same config (with an
    explicit `timestamp`) must produce byte-identical bundles.
    """
    bundle_a = pack_oca_bundle(deepcopy(oca_repro_config))
    bundle_b = pack_oca_bundle(deepcopy(oca_repro_config))

    if bundle_a != bundle_b:
        first_diff = next(
            (i for i, (x, y) in enumerate(zip(bundle_a, bundle_b)) if x != y),
            min(len(bundle_a), len(bundle_b)),
        )
        pytest.fail(
            f"OCA-classic output not deterministic: bundles differ starting at byte {first_diff}; "
            f"lengths: {len(bundle_a)} vs {len(bundle_b)}"
        )


# ---------------------------------------------------------------------------
# Control-plane example determinism: ergonomic IDs + lifecycle + version_range
# pinned timestamp must produce the same bytes on repeated runs.
# ---------------------------------------------------------------------------


def test_control_plane_byte_identical_repeated_runs():
    """The control-plane example config (per-byte chiplet_id + lifecycle named
    list + version_range halves) is byte-deterministic across runs."""
    cfg_path = os.path.join(PROJECT_ROOT, "configs/oca_classic_control_plane_example.yaml")
    cfg_a = _resolve_paths(load_config(cfg_path), PROJECT_ROOT)
    cfg_b = _resolve_paths(load_config(cfg_path), PROJECT_ROOT)

    bundle_a = pack_oca_bundle(cfg_a)
    bundle_b = pack_oca_bundle(cfg_b)

    if bundle_a != bundle_b:
        first_diff = next(
            (i for i, (x, y) in enumerate(zip(bundle_a, bundle_b)) if x != y),
            min(len(bundle_a), len(bundle_b)),
        )
        pytest.fail(
            f"Control-plane bundle not deterministic: first diff at byte {first_diff}"
        )


# ---------------------------------------------------------------------------
# Ergonomic-vs-raw equivalence: two configs that describe the same selection
# (one via the dict-shaped ergonomic input, the other via raw selector_bits +
# a hex-string identity) must produce byte-identical manifest bodies.
# ---------------------------------------------------------------------------


def test_ergonomic_and_raw_configs_produce_identical_bytes(tmp_path):
    """A config expressed ergonomically (`chiplet_id: {0: 0xDE}`) must encode
    to the same bytes as the equivalent raw config (`selector_bits: 0x1` +
    hex-string chiplet_id with byte 0 = 0xDE, remainder 0xA5)."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF" * 4)

    base = {
        "manifest_format": "oca-classic",
        "manifest_identifier": "EQUIV1",
        "description": "ergonomic vs raw equivalence",
        "secure_boot": 0,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [{"type": "EQUIV1XXBLSTAGE1", "path": str(img)}],
    }

    ergonomic = deepcopy(base)
    ergonomic["usage_constraints"] = {"chiplet_id": {0: 0xDE}}

    raw = deepcopy(base)
    raw["usage_constraints"] = {
        "selector_bits": 0x1,
        "chiplet_id": (bytes([0xDE]) + bytes([0xA5]) * 31).hex(),
    }

    bundle_ergonomic = pack_oca_bundle(ergonomic)
    bundle_raw = pack_oca_bundle(raw)

    assert bundle_ergonomic == bundle_raw, (
        "Ergonomic and raw equivalent configs produced different bytes — "
        "selector_bits derivation or 0xA5-fill is off."
    )


# ---------------------------------------------------------------------------
# Legacy-config byte-stability: the canonical OCA-classic example configs
# (which do NOT exercise the new control-plane fields) must remain byte-stable
# after the control-plane addition.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "config_relpath",
    [
        "configs/oca_classic_example.yaml",
        "examples/oca_classic_basic/config.yaml",
    ],
)
def test_legacy_oca_classic_example_byte_stable(config_relpath):
    """Two consecutive packings of a legacy OCA-classic config (no
    usage_constraints fields exercised) yield byte-identical bundles."""
    cfg_path = os.path.join(PROJECT_ROOT, config_relpath)
    cfg_a = _resolve_paths(load_config(cfg_path), PROJECT_ROOT)
    cfg_b = _resolve_paths(load_config(cfg_path), PROJECT_ROOT)

    bundle_a = pack_oca_bundle(cfg_a)
    bundle_b = pack_oca_bundle(cfg_b)

    if bundle_a != bundle_b:
        first_diff = next(
            (i for i, (x, y) in enumerate(zip(bundle_a, bundle_b)) if x != y),
            min(len(bundle_a), len(bundle_b)),
        )
        pytest.fail(
            f"Legacy config {config_relpath} not deterministic: "
            f"first diff at byte {first_diff}"
        )


# ---------------------------------------------------------------------------
# Golden byte-stability guard (both variants).
#
# Determinism (above) proves run-to-run stability; this proves the bytes match
# a known baseline. Manifests are consumed by the boot ROM at fixed offsets
# (byte-stability guarantee), so any change to the packed
# output — Classic or PQC — must be a conscious decision that updates these
# digests, not a silent drift. A failure here means: confirm the change is
# intended, that the validator/boot-ROM consumer still accepts the new bytes,
# then update the golden value.
# ---------------------------------------------------------------------------

# (manifest_identifier, payload type, expected length, expected sha256) per
# variant, for a fixed canonical config (pinned timestamp + fixed payload).
_GOLDEN = {
    "oca-classic": (
        "GOLDEN1", "GOLDEN1XBLSTAGE1", 4920,
        "efff71cd9118c9265abd59c637e98ac6211cd3bf56900c7890b90af0ddbed76b",
    ),
    "oca-pqc": (
        "GOLDENP", "GOLDENPXBLSTAGE1", 37688,
        "4da19c83d5edfa6d07e338e81c802f0e3729c4efbe0ed3833e2a63b10f31c474",
    ),
}


@pytest.mark.parametrize("manifest_format", ["oca-classic", "oca-pqc"])
def test_packed_bytes_match_golden_digest(tmp_path, manifest_format):
    """A fixed canonical config packs to a known SHA-256 for each variant."""
    ident, blstage, expected_len, expected_sha = _GOLDEN[manifest_format]
    img = tmp_path / "img.bin"
    img.write_bytes(bytes(range(256)) * 2)  # 512 fixed bytes
    cfg = {
        "manifest_format": manifest_format,
        "manifest_identifier": ident,
        "description": "golden byte-stability fixture",
        "secure_boot": 0,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 2, "patch": 3},
        "payload_images": [{"type": blstage, "path": str(img)}],
    }
    bundle = pack_oca_bundle(cfg)

    assert len(bundle) == expected_len, (
        f"{manifest_format} bundle length changed: {len(bundle)} != {expected_len}"
    )
    actual_sha = hashlib.sha256(bundle).hexdigest()
    assert actual_sha == expected_sha, (
        f"{manifest_format} packed bytes drifted from the golden digest.\n"
        f"  expected {expected_sha}\n  actual   {actual_sha}\n"
        "If intentional, update _GOLDEN and re-verify the validator/boot-ROM "
        "consumer still accepts the new bytes."
    )


def test_encrypted_bundle_golden_digest(tmp_path):
    """A fixed secure-boot AES-256-CBC encrypted config (pinned secret/IV/KDF
    input) packs to a known SHA-256. A change here means the encrypted output
    bytes drifted — update deliberately after confirming the validator still
    decrypts and accepts the new bytes."""
    img = tmp_path / "img.bin"
    img.write_bytes(bytes(range(256)) * 2)
    cfg = {
        "manifest_format": "oca-classic",
        "manifest_identifier": "ENCGOLD",
        "description": "encrypted golden byte-stability fixture",
        "secure_boot": 1,
        "signature_type": 0x01,
        "signing_authority": "local",
        "signing_key_file": os.path.join(PROJECT_ROOT, "tests/signing_keys/rsa_private_key.f4.pem"),
        "public_key_select_classic": 0x01,
        "encrypted_payload": 1,
        "encryption_type": 0x02,
        "encryption_key_derivation_function": 0x0001,
        "encryption_shared_secret_select": 1,
        "encryption_secret": "00" * 32,
        "encryption_iv": "10" * 16,
        "encryption_kdf_input": "a5" * 64,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 2, "patch": 3},
        "payload_images": [{"type": "ENCGOLDXBLSTAGE1", "path": str(img)}],
    }
    bundle = pack_oca_bundle(cfg)
    assert len(bundle) == 4928
    actual_sha = hashlib.sha256(bundle).hexdigest()
    assert actual_sha == "21f67d4adbaf3b671bcfffc865891e2556fe41e397f7203f8ff23b72392e7879", (
        f"encrypted bundle drifted from the golden digest; got {actual_sha}"
    )
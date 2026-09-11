# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Deferred-feature and shape-error rejection for OCA-classic configs.

Every OCA capability that the packer does not yet implement MUST be rejected
fast with an actionable error that names the offending field and the
deferred feature. Malformed `manifest_identifier`, missing required fields,
oversized `description`, and empty `payload_images` are also rejected at
config-load time with named field errors.
"""

from __future__ import annotations

import io
import os
import re
import time

import pytest

from tt_boot_manifest.oca import entry as oca_entry
from tt_boot_manifest.oca.validators import OcaConfigError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _base_config(tmp_path):
    """Minimal *valid* OCA-classic config. Each test mutates one field to
    trigger the rejection path it wants to verify."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF")
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "DEMO1",
        "description": "valid baseline",
        "secure_boot": 0,
        "timestamp": 1764633600,
        "payload_images": [{"type": "DEMO1_X_BLSTAGE1", "path": str(img)}],
    }


def test_oca_pqc_format_accepted(tmp_path):
    # The selector produces an OCAP, 36864-byte body. PQC-native crypto stays
    # deferred; that rejection is covered in tests/test_oca_pqc.py.
    cfg = _base_config(tmp_path)
    cfg["manifest_format"] = "oca-pqc"
    bundle = oca_entry.pack_oca_bundle(cfg)
    assert bundle[0:4] == b"OCAP"
    assert len(bundle) >= 36864


@pytest.mark.parametrize(
    "field,value",
    [
        ("encryption_kem_dek", "00" * 16),
        ("encryption_key_encapsulation_function", 1),
        ("encryption_kem_unwrap_key_select", 1),
    ],
)
def test_kem_key_wrapping_rejected(tmp_path, field, value):
    """KEM-wrapped payload-encryption keys remain deferred. The supported
    AES-128-CBC + KBKDF encryption path (pre-shared secret) is exercised in
    tests/test_oca_encryption.py."""
    cfg = _base_config(tmp_path)
    cfg[field] = value
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "KEM key wrapping"
    assert exc.value.field_name == field


@pytest.mark.parametrize(
    "field,value",
    [
        ("use_verifier_key", 1),
        ("verifier_key_id_revoke", "ffff"),
        ("verifier_security_version", 1),
    ],
)
def test_verifier_key_rejected(tmp_path, field, value):
    cfg = _base_config(tmp_path)
    cfg[field] = value
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "Verifier-key entry"
    assert exc.value.field_name == field


@pytest.mark.parametrize("bit", range(8))
def test_any_co_signer_bit_rejected(tmp_path, bit):
    cfg = _base_config(tmp_path)
    cfg["co_signer_enable"] = 1 << bit
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "Co-signer entries"
    assert exc.value.field_name == "co_signer_enable"


def test_co_signers_list_nonempty_rejected(tmp_path):
    cfg = _base_config(tmp_path)
    cfg["co_signers"] = [{"key_id": "x"}]
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "Co-signer entries"
    assert exc.value.field_name == "co_signers"


@pytest.mark.parametrize("sig_type", [0x02, 0x03, 0x04, 0x06, 0x07, 0x0A, 0x0B, 0xF0])
def test_unsupported_signature_algorithm_rejected(tmp_path, sig_type):
    cfg = _base_config(tmp_path)
    cfg["secure_boot"] = 1
    cfg["signature_type"] = sig_type
    cfg["signing_authority"] = "local"
    cfg["signing_key_name"] = "test"
    cfg["signing_key_id"] = "x"
    cfg["signing_key_file"] = "tests/signing_keys/rsa_private_key.dev0.pem"
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "Unsupported signature algorithm"
    assert exc.value.field_name == "signature_type"


def test_supported_signature_types_not_rejected_by_deferred_check(tmp_path):
    """Sanity: 0x01 and 0x05 must NOT be flagged as deferred features —
    they're the supported set. They may still raise downstream when secure
    boot signing isn't wired up, but NOT OcaConfigError with the
    `Unsupported signature algorithm` reason."""
    for sig_type in (0x01, 0x05):
        cfg = _base_config(tmp_path)
        cfg["secure_boot"] = 1
        cfg["signature_type"] = sig_type
        cfg["signing_authority"] = "local"
        cfg["signing_key_name"] = "test"
        cfg["signing_key_id"] = "x"
        cfg["signing_key_file"] = "tests/signing_keys/rsa_private_key.dev0.pem"
        try:
            oca_entry.pack_oca_bundle(cfg)
        except OcaConfigError as e:
            if e.deferred_feature == "Unsupported signature algorithm":
                pytest.fail(f"signature_type {sig_type:#x} was flagged as deferred but is supported")
        except Exception:
            # Any other downstream failure is acceptable for this sanity check.
            pass


@pytest.mark.parametrize("field", ["manifest_hash_type", "payload_hash_type"])
@pytest.mark.parametrize("hash_type", [0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
def test_unsupported_hash_algorithm_rejected(tmp_path, field, hash_type):
    cfg = _base_config(tmp_path)
    cfg[field] = hash_type
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "Hash algorithms beyond SHA-256"
    assert exc.value.field_name == field


def test_hsm_signing_authority_rejected(tmp_path):
    cfg = _base_config(tmp_path)
    cfg["secure_boot"] = 1
    cfg["signing_authority"] = "hsm"
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "HSM signing authority"
    assert exc.value.field_name == "signing_authority"


@pytest.mark.parametrize(
    "bad",
    [
        "",            # empty
        "TOOLONG99",   # 9 chars
        "non-asc\x80", # non-ASCII
        "with\x00nul", # NUL byte
    ],
)
def test_manifest_identifier_malformed_rejected(tmp_path, bad):
    cfg = _base_config(tmp_path)
    cfg["manifest_identifier"] = bad
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.field_name == "manifest_identifier"


def test_missing_manifest_identifier_for_oca_classic_rejected(tmp_path):
    cfg = _base_config(tmp_path)
    del cfg["manifest_identifier"]
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.field_name == "manifest_identifier"
    assert "missing required field for oca-classic" in str(exc.value)


def test_description_longer_than_127_chars_rejected(tmp_path):
    cfg = _base_config(tmp_path)
    cfg["description"] = "x" * 128
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.field_name == "description"
    assert "127" in str(exc.value)


def test_image_count_zero_rejected(tmp_path):
    """Empty payload_images is rejected at config-load time, not silently
    turned into a zero-image payload."""
    cfg = _base_config(tmp_path)
    cfg["payload_images"] = []
    with pytest.raises(OcaConfigError) as exc:
        oca_entry.pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"


def test_error_emitted_within_one_second(tmp_path):
    cfg = _base_config(tmp_path)
    cfg["encrypted_payload"] = 1  # representative deferred feature
    start = time.perf_counter()
    with pytest.raises(OcaConfigError):
        oca_entry.pack_oca_bundle(cfg)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"Rejection took {elapsed:.3f}s; budget is 1.0s"


def test_error_message_format_via_cli(tmp_path, capsys):
    """The CLI surface (`pack_images.pack_images()`) catches OcaConfigError
    and renders it to stderr in the format:

        error: OCA feature deferred to future pass: <name> (field <name>)

    or for shape errors:

        error: <field>: <reason>
    """
    from tt_boot_manifest import pack_images

    # Write a YAML config that triggers a deferred feature.
    config_path = tmp_path / "deferred.yaml"
    config_path.write_text(
        "manifest_format: oca-classic\n"
        "manifest_identifier: DEMO1\n"
        "description: triggers deferred\n"
        "secure_boot: 0\n"
        "co_signer_enable: 1\n"  # deferred feature
        "payload_images:\n"
        "  - type: DEMO1_X_BLSTAGE1\n"
        f"    path: {tmp_path}/img.bin\n"
    )
    (tmp_path / "img.bin").write_bytes(b"\xDE\xAD\xBE\xEF")

    out_path = tmp_path / "out.bin"
    ok = pack_images.pack_images(str(config_path), str(out_path), verbose=False)

    assert ok is False, "CLI must report failure when OCA rejection fires"
    captured = capsys.readouterr()
    deferred_lines = [
        ln for ln in captured.err.splitlines()
        if re.match(r"^error: OCA feature deferred to future pass: [^()]+ \(field [a-z_]+\)$", ln)
    ]
    assert len(deferred_lines) == 1, (
        f"Expected exactly one 'error: OCA feature deferred...' line in stderr; "
        f"got stderr:\n{captured.err!r}"
    )
    # The file MUST NOT have been written (rejection is fail-fast).
    assert not out_path.exists(), "Output file should not be created on rejection"


# ---------------------------------------------------------------------------
# Mode-conflict rejection at the usage_constraints layer: fast (<1s) and
# rendered to stderr as a single-line `error: usage_constraints: ...`.
# ---------------------------------------------------------------------------


def test_usage_constraints_mode_conflict_emitted_within_one_second(tmp_path):
    """Mixing raw selector_bits with an ergonomic shape is rejected by the
    entry surface in well under 1 second."""
    cfg = _base_config(tmp_path)
    cfg["usage_constraints"] = {
        "selector_bits": 0x05,
        "lifecycle_chiplet_states": ["TEST_DEV"],
    }
    start = time.perf_counter()
    with pytest.raises(OcaConfigError):
        oca_entry.pack_oca_bundle(cfg)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"Rejection took {elapsed:.3f}s; budget is 1.0s"


def test_usage_constraints_mode_conflict_message_format_via_cli(tmp_path, capsys):
    """The CLI surface renders the mode-conflict error as a single line in
    the `error: <field>: <reason>` format used by the OCA config validators'
    shape rejections."""
    from tt_boot_manifest import pack_images

    config_path = tmp_path / "conflict.yaml"
    config_path.write_text(
        "manifest_format: oca-classic\n"
        "manifest_identifier: DEMO1\n"
        "description: triggers mode conflict\n"
        "secure_boot: 0\n"
        "usage_constraints:\n"
        "  selector_bits: 5\n"
        "  lifecycle_chiplet_states: [TEST_DEV]\n"
        "payload_images:\n"
        "  - type: DEMO1_X_BLSTAGE1\n"
        f"    path: {tmp_path}/img.bin\n"
    )
    (tmp_path / "img.bin").write_bytes(b"\xDE\xAD\xBE\xEF")

    out_path = tmp_path / "out.bin"
    ok = pack_images.pack_images(str(config_path), str(out_path), verbose=False)

    assert ok is False, "CLI must report failure when mode-conflict fires"
    captured = capsys.readouterr()
    conflict_lines = [
        ln for ln in captured.err.splitlines()
        if re.match(r"^error: usage_constraints: ", ln)
    ]
    assert len(conflict_lines) == 1, (
        f"Expected exactly one 'error: usage_constraints: ...' line in stderr; "
        f"got stderr:\n{captured.err!r}"
    )
    assert not out_path.exists(), "Output file should not be created on rejection"

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Format dispatch in src/pack_images.py.

Tests that every `oca-*` selector routes to its packer, and that a missing
or unknown `manifest_format` fails fast with a named error — both from the
programmatic surface (generate_images) and the CLI surface (pack_images).
"""

from __future__ import annotations

import pytest

from tt_boot_manifest import pack_images
from tt_boot_manifest.oca import combined as oca_combined
from tt_boot_manifest.oca import entry as oca_entry


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _oca_minimal_config():
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "DEMO1",
        "description": "minimal oca-classic",
        "secure_boot": 0,
        "payload_images": [
            {"type": "OCADEMO1BLSTAGE1", "path": "tests/oca_fixtures/dummy_image.bin"},
        ],
    }


def _write_config_missing_format(tmp_path):
    config_path = tmp_path / "noformat.yaml"
    config_path.write_text(
        "manifest_identifier: DEMO1\n"
        "description: no manifest_format\n"
        "secure_boot: 0\n"
        "payload_images:\n"
        "  - type: DEMO1_X_BLSTAGE1\n"
        f"    path: {tmp_path}/img.bin\n"
    )
    (tmp_path / "img.bin").write_bytes(b"\xDE\xAD\xBE\xEF")
    return config_path


# ---------------------------------------------------------------------------
# Programmatic surface: generate_images()
# ---------------------------------------------------------------------------


def test_missing_manifest_format_raises():
    """A config without 'manifest_format' raises a ValueError that names the
    field and the accepted set — there is no default format."""
    cfg = _oca_minimal_config()
    del cfg["manifest_format"]
    with pytest.raises(ValueError) as excinfo:
        pack_images.generate_images(cfg)
    msg = str(excinfo.value)
    assert "manifest_format" in msg
    assert "oca-classic" in msg
    assert "oca-pqc" in msg
    assert "oca-combined" in msg


def test_unknown_manifest_format_raises():
    """A manifest_format value outside the accepted set raises a ValueError
    that names both the bad value and the accepted set."""
    cfg = _oca_minimal_config()
    cfg["manifest_format"] = "bogus"
    with pytest.raises(ValueError) as excinfo:
        pack_images.generate_images(cfg)
    msg = str(excinfo.value)
    assert "bogus" in msg
    assert "oca-classic" in msg
    assert "oca-pqc" in msg
    assert "oca-combined" in msg


@pytest.mark.parametrize("fmt", ["oca-classic", "oca-pqc"])
def test_oca_bundle_formats_dispatch_to_oca_entry(monkeypatch, fmt):
    """`manifest_format: oca-classic` / `oca-pqc` route execution into
    src/oca/entry.pack_oca_bundle with the parsed config dict."""
    cfg = _oca_minimal_config()
    cfg["manifest_format"] = fmt
    captured = {}

    def fake_entry(config, output_path=None, verbose=False):
        captured["config"] = config
        captured["output_path"] = output_path
        captured["verbose"] = verbose
        # Mimic a successful run by returning a sentinel; the real entry
        # returns bundle bytes / writes to disk.
        return b"\x00"

    monkeypatch.setattr(oca_entry, "pack_oca_bundle", fake_entry)

    pack_images.generate_images(cfg)

    assert captured["config"] is cfg
    # No output_path was supplied via generate_images; entry receives None.
    assert captured["output_path"] is None


def test_oca_combined_dispatches_to_combined(monkeypatch):
    """`manifest_format: oca-combined` routes execution into
    src/oca/combined.pack_combined_image with the parsed config dict."""
    cfg = _oca_minimal_config()
    cfg["manifest_format"] = "oca-combined"
    captured = {}

    def fake_combined(config, output_path=None, verbose=False):
        captured["config"] = config
        return b"\x00"

    monkeypatch.setattr(oca_combined, "pack_combined_image", fake_combined)

    pack_images.generate_images(cfg)

    assert captured["config"] is cfg


# ---------------------------------------------------------------------------
# CLI surface: missing/unknown manifest_format produces an error consistent
# with the deferred-feature error UX (single-line, "error: ..." on stderr).
# ---------------------------------------------------------------------------


def test_unknown_manifest_format_cli_renders_consistent_error(tmp_path, capsys):
    """When the CLI surface (`pack_images.pack_images()`) encounters an unknown
    manifest_format value, it must render a single-line `error: ...` message
    on stderr — matching the shape used for OCA deferred-feature rejections,
    so producers see a consistent UX across selector-typo and
    deferred-feature paths."""
    config_path = tmp_path / "bogus.yaml"
    config_path.write_text(
        "manifest_format: not-a-real-format\n"
        "manifest_identifier: DEMO1\n"
        "description: bogus\n"
        "secure_boot: 0\n"
        "payload_images:\n"
        "  - type: DEMO1_X_BLSTAGE1\n"
        f"    path: {tmp_path}/img.bin\n"
    )
    (tmp_path / "img.bin").write_bytes(b"\xDE\xAD\xBE\xEF")

    out_path = tmp_path / "out.bin"
    ok = pack_images.pack_images(str(config_path), str(out_path), verbose=False)

    assert ok is False
    captured = capsys.readouterr()
    error_lines = [ln for ln in captured.err.splitlines() if ln.startswith("error:")]
    assert error_lines, (
        f"Expected at least one 'error: ...' line on stderr; got:\n{captured.err!r}"
    )
    # The error must mention both the bad value and the allowed set.
    joined = "\n".join(error_lines)
    assert "not-a-real-format" in joined
    assert "oca-classic" in joined and "oca-pqc" in joined and "oca-combined" in joined
    assert not out_path.exists()


def test_missing_manifest_format_cli_errors(tmp_path, capsys):
    """A config file without manifest_format is rejected by the CLI surface
    with a single `error: ...` line naming the field, and no output file."""
    config_path = _write_config_missing_format(tmp_path)

    out_path = tmp_path / "out.bin"
    ok = pack_images.pack_images(str(config_path), str(out_path), verbose=False)

    assert ok is False
    captured = capsys.readouterr()
    error_lines = [ln for ln in captured.err.splitlines() if ln.startswith("error:")]
    assert len(error_lines) == 1, (
        f"Expected exactly one 'error: ...' line on stderr; got:\n{captured.err!r}"
    )
    assert "manifest_format" in error_lines[0]
    assert not out_path.exists()

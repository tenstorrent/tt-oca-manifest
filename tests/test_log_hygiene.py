# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Packing never writes encryption secrets to the log.

Key material and IVs must never be logged at any verbosity level. Each packing
entry point runs at DEBUG over a config that carries every secret-bearing
encryption field, and the captured log and console output must hold none of
their values in any common rendering.
"""

from __future__ import annotations

import logging

from tt_boot_manifest import pack_images
from tt_boot_manifest.oca.combined import pack_combined_image
from tt_boot_manifest.utils import load_config

ENCRYPTED_CONFIG = "configs/oca_encrypted_example.yaml"
SECRET_FIELDS = ("encryption_secret", "encryption_iv", "encryption_kdf_input")


def _secret_renderings(config):
    renderings = []
    for field in SECRET_FIELDS:
        value = bytes.fromhex(str(config[field]))
        renderings += [value.hex(), value.hex().upper(), repr(value)]
    return renderings


def _leaked(text, config):
    """Return every rendering of a secret field's value that appears in text."""
    return [rendering for rendering in _secret_renderings(config) if rendering in text]


def _combined_config(bank_config_path):
    return {
        "manifest_format": "oca-combined",
        "name": "log hygiene",
        "combos": [
            {
                "name": "encrypted",
                "config": bank_config_path,
                "manifest_offset": 0x0,
                "payload_offset": 0x1000,
            },
        ],
    }


def _debug_was_captured(caplog):
    return any(record.levelno == logging.DEBUG for record in caplog.records)


def test_leak_check_detects_a_logged_secret(caplog):
    caplog.set_level(logging.DEBUG)
    config = load_config(ENCRYPTED_CONFIG)
    logging.getLogger("log_hygiene_probe").debug("config: %s", config)
    assert _leaked(caplog.text, config)


def test_leak_check_passes_clean_text():
    config = load_config(ENCRYPTED_CONFIG)
    assert _leaked("manifest_identifier=ENCDEMO", config) == []


def test_generate_images_logs_no_secret(caplog):
    caplog.set_level(logging.DEBUG)
    config = load_config(ENCRYPTED_CONFIG)
    images = pack_images.generate_images(config)
    assert len(images) == 1 and images[0]
    assert _debug_was_captured(caplog)
    assert _leaked(caplog.text, config) == []


def test_verbose_cli_logs_no_secret(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    config = load_config(ENCRYPTED_CONFIG)
    assert pack_images.pack_images(ENCRYPTED_CONFIG, str(tmp_path / "enc.bin"), verbose=True)
    console = capsys.readouterr()
    assert _debug_was_captured(caplog)
    assert _leaked(caplog.text + console.out + console.err, config) == []


def test_combined_image_logs_no_bank_secret(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    bank_config = load_config(ENCRYPTED_CONFIG)
    combined = _combined_config(ENCRYPTED_CONFIG)
    assert pack_images.generate_images(combined)[0]
    assert pack_combined_image(combined, output_path=str(tmp_path / "img.bin"), verbose=True)
    console = capsys.readouterr()
    assert _debug_was_captured(caplog)
    assert _leaked(caplog.text + console.out + console.err, bank_config) == []

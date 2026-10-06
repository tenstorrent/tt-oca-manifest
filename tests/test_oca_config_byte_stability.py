# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Byte-stability pins for every committed OCA config.

Each buildable config under `configs/`, `examples/` and the validator fixture
directory is packed exactly as `python -m tt_boot_manifest.pack_images` would
pack it from the repository root, and the output is compared against a pinned
length and SHA-256. A change to the packer that alters the bytes of any existing
config fails here, naming the config, rather than shipping as a silent layout
drift.

A failure means one of two things. Either the change was not meant to touch
existing output, and the packer is wrong; or it was, and the change is breaking
for the boot ROM: update the pin in the same commit, and put the regenerated
binary diff in the pull request description.

Every config must be pinned or listed in `_UNBUILDABLE`, so a newly added
config cannot go unpinned.
"""

from __future__ import annotations

import glob
import hashlib
import os

import pytest

from tt_boot_manifest.pack_images import generate_images
from tt_boot_manifest.utils import load_config

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG_GLOBS = (
    "configs/*.yaml",
    "examples/*/config.yaml",
    "validators/oca/test/fixtures/configs/*.yaml",
)

# repo-relative config path -> (packed length, SHA-256 of the packed bytes)
_PINNED = {
    "configs/oca_classic_control_plane_example.yaml": (
        4412, "701b84399cee1ec0104e8eda84a187f72be482383b23f82a4f529be2af523216"),
    "configs/oca_classic_example.yaml": (
        4416, "faa75758fcf873c97fb856d3407486f13587a15c3b9811f6bb96d57cd38cb535"),
    "configs/oca_combined_example.yaml": (
        131072, "a8ccc76ae3324a6f65f69848ebfed4b36988354829d08cb707f1a6b83539c018"),
    "configs/oca_encrypted_example.yaml": (
        4432, "3beb4472ce7c886cd9d13efa268dfce31e38743862a0d6c03fde0d13d6c127b1"),
    "configs/oca_pqc_example.yaml": (
        37184, "45b5942978d04d0f9f0ccea33cd80d4d9f54899c747e78e7e885ac7d644514a0"),
    "configs/oca_secure_boot_device_state_example.yaml": (
        4416, "dd4880e2acc67bd8f77766aa872614c2a0e37e45ceb3aaae278c46fc803103dc"),
    "examples/oca_classic_basic/config.yaml": (
        4412, "32393bdabd0ca13ec3ed5c52f1a88c9886f5803ce88119bceee54ff8626aec62"),
    "validators/oca/test/fixtures/configs/all_constraints.yaml": (
        4412, "f5afa192f8e79173bcf7e6bc33af344f6583b2358a69f5c97e0e800126a883a3"),
    "validators/oca/test/fixtures/configs/basic.yaml": (
        4412, "f2868492d39c1a187577a08c180ef104215ed19ec8bd98bdc34ee401599de5e3"),
    "validators/oca/test/fixtures/configs/control_plane.yaml": (
        4412, "c8051275bb083c6d88438cde731efa5a725077eececeba626e2d447bf940b675"),
    "validators/oca/test/fixtures/configs/encrypted_aes.yaml": (
        4416, "4ab13efc8a810abab38436a453c7df3fae3d12cfaa0f01acc93eb742dbe55f43"),
    "validators/oca/test/fixtures/configs/encrypted_aes_pqc.yaml": (
        37184, "04f7be71675d3889b13df79b8e5a1f6f006125e47cc4f707bcf160c53830754a"),
    "validators/oca/test/fixtures/configs/multi_image.yaml": (
        4988, "78a5b7fd631c75d1c6e3945dde69ee35faac4c8f6176eccab1679b4f07045405"),
    "validators/oca/test/fixtures/configs/pqc_basic.yaml": (
        37180, "24eaca9a37f9f468708d252231ea35a7db89d887f054b2f2857c9316865e01ec"),
    "validators/oca/test/fixtures/configs/pqc_secure_rsa.yaml": (
        37180, "1d12fcd74ed2cd837f97e5802d7da91904285603e548bc2c6163079c56e4c19d"),
    "validators/oca/test/fixtures/configs/secure_ecdsa.yaml": (
        4412, "02805cd27008fef796e0959389c6c285d5aa471bb3a0dc02e6532fe78ea1b8ab"),
    "validators/oca/test/fixtures/configs/secure_rsa.yaml": (
        4412, "2a0d0eecef8089e98f868c7ecf6847efc4c310416ff348c5043c7d4b147ce091"),
    "validators/oca/test/fixtures/configs/secure_rsa_der.yaml": (
        4412, "3fec990e2ea3c264165f9e02b3ca3866a39d58c2f22e7f26e3aadfdaf16d4449"),
    "validators/oca/test/fixtures/configs/secure_rsa_e3.yaml": (
        4412, "15b3df2cc70cc8a9c307a9a210910f1a3b11a0e445f398ede94a29ef2aeeaaae"),
    "validators/oca/test/fixtures/configs/secure_rsa_e3_der.yaml": (
        4412, "acbe691af844f7767fe71e4f1f474681e219e9c3021e137609c4cd7d65e17366"),
}

# repo-relative config path -> why it is not packed here. Never pack these: the
# production template names a KMS signing authority, so an attempt reaches the
# network with whatever credentials the host happens to hold.
_UNBUILDABLE = {
    "configs/oca_production_template.yaml":
        "placeholder KMS key and payload path; deliberately does not build from a clean checkout",
}


def _committed_configs():
    """Every config the pin table must account for, as repo-relative paths."""
    found = set()
    for pattern in CONFIG_GLOBS:
        for path in glob.glob(os.path.join(PROJECT_ROOT, pattern)):
            found.add(os.path.relpath(path, PROJECT_ROOT).replace(os.sep, "/"))
    return found


def _pack(config_relpath):
    """Pack a committed config from the repository root, as the CLI would."""
    prev = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        return generate_images(load_config(config_relpath))[0]
    finally:
        os.chdir(prev)


@pytest.mark.parametrize("config_relpath", sorted(_PINNED))
def test_committed_config_packs_to_pinned_bytes(config_relpath):
    """Each buildable config packs to exactly its pinned length and digest."""
    expected_len, expected_sha = _PINNED[config_relpath]
    packed = _pack(config_relpath)

    assert len(packed) == expected_len, (
        f"{config_relpath}: packed length changed: {len(packed)} != {expected_len}")
    actual_sha = hashlib.sha256(packed).hexdigest()
    assert actual_sha == expected_sha, (
        f"{config_relpath}: packed bytes drifted from the pin.\n"
        f"  expected {expected_sha}\n  actual   {actual_sha}")


def test_every_committed_config_is_pinned_or_explained():
    """No committed config escapes the pin table, and none is listed twice."""
    committed = _committed_configs()

    assert not set(_PINNED) & set(_UNBUILDABLE), \
        "a config is both pinned and listed as unbuildable"
    unaccounted = committed - set(_PINNED) - set(_UNBUILDABLE)
    assert not unaccounted, (
        f"configs with no byte pin: {sorted(unaccounted)}; pin them in _PINNED "
        "or explain them in _UNBUILDABLE")
    stale = (set(_PINNED) | set(_UNBUILDABLE)) - committed
    assert not stale, f"pins for configs that no longer exist: {sorted(stale)}"

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Tests for the OCA combined deployable-image assembler.

Covers multi-bank assembly, overlap rejection, isolation/byte-identity of a
standalone bank vs. the same bank inside the image, auxiliary regions,
single-offset vs. per-image payload placement, determinism, and validation.

A non-secure-boot bank keeps these fast (no signing keys) while still exercising
the full signed-region build path; only the unsigned payload_offset is patched.
"""

from __future__ import annotations

import os
import struct

import pytest

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.combined import pack_combined_image, _payload_image_layout
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError
from tt_boot_manifest.utils import load_config

OCAC_MAGIC = b"OCAC"
PTOC_MAGIC = b"PTOC"


def _make_bank(tmp_path, ident, n_images=1, img_size=16, manifest_format="oca-classic"):
    """Write a minimal non-secure oca-classic bank config + image(s) to disk.

    Returns the config file path (str). Image i is filled with byte (i+1).
    """
    bank_dir = tmp_path / ident
    bank_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        f"manifest_format: {manifest_format}",
        f'manifest_identifier: "{ident}"',
        f'description: "combined test bank {ident}"',
        "secure_boot: 0",
        "timestamp: 1764633600",
        "manifest_content_version:",
        "  major: 1",
        "  minor: 0",
        "  patch: 0",
        "payload_images:",
    ]
    for i in range(n_images):
        img = bank_dir / f"img{i}.bin"
        img.write_bytes(bytes([(i + 1) & 0xFF]) * img_size)
        lines.append(f'  - type: "IMG{i}STAGE"')
        lines.append(f'    path: "{img}"')
    cfg = bank_dir / f"{ident}.yaml"
    cfg.write_text("\n".join(lines) + "\n")
    return str(cfg)


def _standalone(cfg_path):
    return pack_oca_bundle(load_config(cfg_path))


# ---------------------------------------------------------------------------
# Isolation: signed region immutable, payload identical
# ---------------------------------------------------------------------------


def test_signed_region_immutable_and_payload_identical(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    standalone = _standalone(bank)
    payload = standalone[oca_consts.OCA_CLASSIC_BODY_SIZE:]

    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x2000},
        ],
    }
    image = pack_combined_image(cfg)

    # Manifest body sits at offset 0; its signed region must be untouched.
    assert image[0 : oca_consts.OCA_CLASSIC_SIGNED_REGION_END] == standalone[0 : oca_consts.OCA_CLASSIC_SIGNED_REGION_END]
    # Payload placed verbatim at 0x2000.
    assert image[0x2000 : 0x2000 + len(payload)] == payload
    # The only manifest difference is the reconciled (unsigned) payload_offset.
    rel = struct.unpack_from("<q", image, oca_consts.OFF_PAYLOAD_OFFSET)[0]
    assert rel == 0x2000  # payload_base (0x2000) - manifest_offset (0)


def test_bank_byte_identical_when_placed_contiguously(tmp_path):
    """A bank placed exactly as a standalone build (payload right after the
    manifest) is byte-for-byte identical to the standalone bundle."""
    bank = _make_bank(tmp_path, "BANKA")
    standalone = _standalone(bank)

    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0,
             "payload_offset": oca_consts.OCA_CLASSIC_BODY_SIZE},
        ],
    }
    image = pack_combined_image(cfg)
    assert image == standalone


# ---------------------------------------------------------------------------
# Full multi-bank image
# ---------------------------------------------------------------------------


def test_two_bank_image_places_each_combo(tmp_path):
    bank_a = _make_bank(tmp_path, "BANKA")
    bank_b = _make_bank(tmp_path, "BANKB")
    cfg = {
        "manifest_format": "oca-combined",
        "name": "full image",
        "combos": [
            {"name": "primary", "config": bank_a, "manifest_offset": 0x0, "payload_offset": 0x1000},
            {"name": "secondary", "config": bank_b, "manifest_offset": 0x8000, "payload_offset": 0x9000},
        ],
    }
    image = pack_combined_image(cfg)

    assert image[0x0:0x4] == OCAC_MAGIC
    assert image[0x8000:0x8004] == OCAC_MAGIC
    # Each manifest's reconciled payload_offset points at its placed payload.
    assert struct.unpack_from("<q", image, 0x0 + oca_consts.OFF_PAYLOAD_OFFSET)[0] == 0x1000
    assert struct.unpack_from("<q", image, 0x8000 + oca_consts.OFF_PAYLOAD_OFFSET)[0] == 0x1000
    # Payloads begin with the TOC magic at their placed offsets.
    assert image[0x1000:0x1004] == PTOC_MAGIC
    assert image[0x9000:0x9004] == PTOC_MAGIC


def test_mixed_classic_and_pqc_combined_image(tmp_path):
    """A combined image with a Classic combo and a PQC combo places each at its
    own manifest body size (4096 vs 36864), patching each variant's own
    payload_offset field."""
    classic = _make_bank(tmp_path, "BANKA")  # oca-classic, 4096-byte body
    pqc = _make_bank(tmp_path, "BANKP", manifest_format="oca-pqc")  # 36864-byte body
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "classic", "config": classic, "manifest_offset": 0x0, "payload_offset": 0x1000},
            {"name": "pqc", "config": pqc, "manifest_offset": 0x10000, "payload_offset": 0x19000},
        ],
    }
    image = pack_combined_image(cfg)

    assert image[0x0:0x4] == OCAC_MAGIC                 # Classic bank
    assert image[0x10000:0x10004] == b"OCAP"            # PQC bank (36864-byte body)
    # Each manifest's reconciled payload_offset is patched at the variant's field.
    assert struct.unpack_from("<q", image, 0x0 + oca_consts.CLASSIC_VARIANT.payload_offset_field)[0] == 0x1000
    assert struct.unpack_from("<q", image, 0x10000 + oca_consts.PQC_VARIANT.payload_offset_field)[0] == 0x9000
    assert image[0x1000:0x1004] == PTOC_MAGIC
    assert image[0x19000:0x19004] == PTOC_MAGIC


def test_total_size_pads_and_default_pad_byte_is_ff(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "total_size": 0x20000,
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
    }
    image = pack_combined_image(cfg)
    assert len(image) == 0x20000
    # Tail is padded with the default 0xFF.
    assert image[-1] == 0xFF
    assert image[0x1FFF0:0x20000] == b"\xff" * 16


def test_custom_pad_byte(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "total_size": 0x20000,
        "pad_byte": 0x00,
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
    }
    image = pack_combined_image(cfg)
    assert image[-16:] == b"\x00" * 16


def test_region_beyond_total_size_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "total_size": 0x100,  # smaller than a 4096-byte manifest
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "total_size"


# ---------------------------------------------------------------------------
# Overlap prevention (no output on rejection)
# ---------------------------------------------------------------------------


def test_payload_over_own_manifest_rejected_no_output(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    out = tmp_path / "should_not_exist.bin"
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            # payload at 0x800 collides with the manifest [0, 0x1000)
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x800},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg, output_path=str(out))
    assert exc.value.field_name == "layout"
    assert not out.exists()  # nothing written on rejection


def test_two_manifests_overlap_rejected(tmp_path):
    bank_a = _make_bank(tmp_path, "BANKA")
    bank_b = _make_bank(tmp_path, "BANKB")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank_a, "manifest_offset": 0x0, "payload_offset": 0x4000},
            {"name": "secondary", "config": bank_b, "manifest_offset": 0x800, "payload_offset": 0x8000},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "layout"


def test_gaps_filled_when_no_overlap(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x2000},
        ],
    }
    image = pack_combined_image(cfg)
    # Gap between the 4096-byte manifest and the payload at 0x2000 is 0xFF.
    assert image[0x1000:0x2000] == b"\xff" * (0x2000 - 0x1000)


# ---------------------------------------------------------------------------
# Auxiliary regions
# ---------------------------------------------------------------------------


def test_auxiliary_region_placed_verbatim(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    aux = tmp_path / "storage_params.bin"
    aux_bytes = bytes(range(64))
    aux.write_bytes(aux_bytes)
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
        "auxiliary_regions": [
            {"name": "storage_params", "path": str(aux), "offset": 0x8000},
        ],
    }
    image = pack_combined_image(cfg)
    assert image[0x8000:0x8000 + len(aux_bytes)] == aux_bytes


def test_auxiliary_missing_file_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
        "auxiliary_regions": [
            {"name": "missing", "path": str(tmp_path / "nope.bin"), "offset": 0x8000},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "auxiliary_regions[0].path"


def test_auxiliary_overlap_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    aux = tmp_path / "aux.bin"
    aux.write_bytes(b"\xAA" * 256)
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
        "auxiliary_regions": [
            {"name": "aux", "path": str(aux), "offset": 0x10},  # lands inside the manifest
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "layout"


# ---------------------------------------------------------------------------
# Per-image payload placement (single base or explicit list)
# ---------------------------------------------------------------------------


def test_payload_offset_list_places_each_image(tmp_path):
    bank = _make_bank(tmp_path, "BANKM", n_images=2, img_size=16)
    standalone = _standalone(bank)
    payload = standalone[oca_consts.OCA_CLASSIC_BODY_SIZE:]
    layout = _payload_image_layout(payload)
    assert len(layout) == 2

    base = 0x1000  # contiguous after the manifest
    offsets = [base + rel for (rel, _length) in layout]
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": offsets},
        ],
    }
    image = pack_combined_image(cfg)
    for (rel, length), off in zip(layout, offsets):
        assert image[off:off + length] == payload[rel:rel + length]


def test_payload_offset_list_count_mismatch_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKM", n_images=2)
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": [0x1000]},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "combos[0].payload_offset"


def test_payload_offset_list_inconsistent_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKM", n_images=2)
    standalone = _standalone(bank)
    layout = _payload_image_layout(standalone[oca_consts.OCA_CLASSIC_BODY_SIZE:])
    base = 0x1000
    offsets = [base + rel for (rel, _length) in layout]
    offsets[1] += 8  # perturb one image so it can't share a single base
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": offsets},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "combos[0].payload_offset"


# ---------------------------------------------------------------------------
# Determinism, regression, and validation coverage
# ---------------------------------------------------------------------------


def test_determinism(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
    }
    assert pack_combined_image(cfg) == pack_combined_image(cfg)


def test_oca_classic_path_unchanged_through_generate_images(tmp_path):
    """Regression: the added dispatch branch leaves the oca-classic path intact."""
    from tt_boot_manifest.pack_images import generate_images
    bank = _make_bank(tmp_path, "BANKA")
    cfg = load_config(bank)
    assert generate_images(cfg) == [pack_oca_bundle(load_config(bank))]


def test_negative_offset_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": -16, "payload_offset": 0x1000},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "combos[0].manifest_offset"


def test_misaligned_payload_offset_rejected(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x1001},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "combos[0].payload_offset"


def test_duplicate_name_rejected(tmp_path):
    bank_a = _make_bank(tmp_path, "BANKA")
    bank_b = _make_bank(tmp_path, "BANKB")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "dup", "config": bank_a, "manifest_offset": 0x0, "payload_offset": 0x1000},
            {"name": "dup", "config": bank_b, "manifest_offset": 0x8000, "payload_offset": 0x9000},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name == "combos[1].name"


def test_single_combo_accepted(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "only", "config": bank, "manifest_offset": 0, "payload_offset": 0x1000},
        ],
    }
    image = pack_combined_image(cfg)
    assert image[0:4] == OCAC_MAGIC


def test_errors_are_single_line_with_field(tmp_path):
    bank = _make_bank(tmp_path, "BANKA")
    cfg = {
        "manifest_format": "oca-combined",
        "combos": [
            {"name": "primary", "config": bank, "manifest_offset": 0, "payload_offset": 0x800},
        ],
    }
    with pytest.raises(OcaConfigError) as exc:
        pack_combined_image(cfg)
    assert exc.value.field_name
    assert exc.value.reason
    assert "\n" not in exc.value.reason

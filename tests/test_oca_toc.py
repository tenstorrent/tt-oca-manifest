# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Bundle multiple images via the OCA payload TOC.

Tests the multi-image payload pipeline: PTOC header, 276-byte TOC entries,
ascending-offset ordering, no overlap, 8-byte alignment, per-entry image
hashes, payload_hash over the TOC region, and the iterative
payload_hash_chain construction.

Also pins the complete "Payload TOC entry" byte layout — every field at its
spec offset, reserved regions zeroed — using literal offsets rather than the
packer's own constants, so a layout regression fails here instead of shipping.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_image(tmp_path, name: str, payload: bytes):
    p = tmp_path / name
    p.write_bytes(payload)
    return str(p)


def _multi_image_config(tmp_path, images_data, extra=None):
    """images_data: list of (label, bytes) pairs.

    `extra` is an optional dict merged into every payload_images entry, for
    exercising the optional TOC-entry fields.
    """
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "MULTI1",
        "description": "multi-image oca-classic test",
        "secure_boot": 0,
        "timestamp": 1764633600,
        "payload_images": [
            {
                "type": (f"MULTI1__{label}").ljust(16),
                "path": _make_image(tmp_path, f"{label}.bin", data),
                **(extra or {}),
            }
            for label, data in images_data
        ],
    }


def _split_bundle(bundle):
    """Return (manifest_body, payload_bytes)."""
    return bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE], bundle[oca_consts.OCA_CLASSIC_BODY_SIZE :]


def _toc_entries(payload, image_count):
    """Iterate (start_offset_within_payload, entry_bytes) for each TOC entry."""
    base = oca_consts.TOC_HEADER_SIZE
    for i in range(image_count):
        start = base + i * oca_consts.TOC_ENTRY_SIZE
        yield start, payload[start : start + oca_consts.TOC_ENTRY_SIZE]


# The full "Payload TOC entry" layout, spelled out in literal byte offsets
# rather than via oca_consts, so these tests independently pin the layout the
# spec table defines. A drift in constants.py must fail here, not be masked.
_SPEC_ENTRY_LAYOUT = {
    "type": (0, 16),
    "group": (16, 4),
    "offset": (20, 8),
    "length": (28, 8),
    "version": (36, 8),
    "security_version": (44, 8),
    "load_addr": (52, 8),
    "entry_point": (60, 8),
    "target_chiplet_id": (68, 8),
    "reserved_1": (76, 4),
    "hash": (80, 64),
    "description": (144, 128),
    "reserved_2": (272, 4),
}

_SPEC_U64_FIELDS = ("offset", "length", "version", "security_version",
                    "load_addr", "entry_point", "target_chiplet_id")


def _entry_raw(entry: bytes, name: str) -> bytes:
    """Slice one field out of a TOC entry by its spec offset/size."""
    off, size = _SPEC_ENTRY_LAYOUT[name]
    return entry[off:off + size]


def _entry_fields(entry: bytes):
    """Unpack every subfield of a TOC entry per the spec's Payload TOC entry
    table (see _SPEC_ENTRY_LAYOUT). Integer fields come back as ints; `type`,
    `hash`, `description`, and the reserved regions come back as raw bytes."""
    assert len(entry) == oca_consts.TOC_ENTRY_SIZE
    out = {name: _entry_raw(entry, name) for name in _SPEC_ENTRY_LAYOUT}
    out["group"] = struct.unpack_from("<I", entry, 16)[0]
    for name in _SPEC_U64_FIELDS:
        off, _ = _SPEC_ENTRY_LAYOUT[name]
        out[name] = struct.unpack_from("<Q", entry, off)[0]
    return out


def test_toc_header_starts_with_ptoc_8byte_aligned(tmp_path):
    cfg = _multi_image_config(tmp_path, [("a", b"\x01" * 16)])
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    # Manifest body is 4096 bytes (multiple of 8) → payload starts on an 8-byte boundary.
    assert oca_consts.OCA_CLASSIC_BODY_SIZE % 8 == 0
    assert payload[0:4] == b"PTOC"


def test_image_count_matches_config_four_images(tmp_path):
    cfg = _multi_image_config(
        tmp_path,
        [("a", b"A" * 8), ("b", b"B" * 16), ("c", b"C" * 32), ("d", b"D" * 64)],
    )
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    image_count = struct.unpack_from("<Q", payload, 16)[0]
    assert image_count == 4
    # Sanity: header is 32 bytes, then 4 × 276-byte entries follow.
    assert len(payload) >= oca_consts.TOC_HEADER_SIZE + 4 * oca_consts.TOC_ENTRY_SIZE


def test_entries_ordered_by_ascending_offset(tmp_path):
    cfg = _multi_image_config(
        tmp_path,
        [("a", b"A" * 8), ("b", b"B" * 16), ("c", b"C" * 32), ("d", b"D" * 64)],
    )
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    offsets = [_entry_fields(e)["offset"] for _, e in _toc_entries(payload, 4)]
    assert offsets == sorted(offsets), f"TOC offsets not ascending: {offsets}"
    # Strict ascending (no duplicates).
    assert len(set(offsets)) == len(offsets)


def test_overlapping_offsets_rejected(tmp_path):
    cfg = _multi_image_config(tmp_path, [("a", b"A" * 64), ("b", b"B" * 64)])
    # Force overlap: image a covers payload-bytes [600, 664); image b at offset 640 (overlaps).
    cfg["payload_images"][0]["offset"] = 600
    cfg["payload_images"][0]["length"] = 64
    cfg["payload_images"][1]["offset"] = 640
    cfg["payload_images"][1]["length"] = 64
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"
    msg = str(exc.value)
    assert "overlap" in msg.lower()


def test_unaligned_image_offset_rejected(tmp_path):
    cfg = _multi_image_config(tmp_path, [("a", b"A" * 8)])
    cfg["payload_images"][0]["offset"] = 0x123  # not multiple of 8
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"
    msg = str(exc.value)
    assert "align" in msg.lower() or "0x123" in msg.lower() or "8" in msg


def test_per_entry_hash_matches_image_bytes(tmp_path):
    data = [("a", b"alpha-image-bytes" * 4),
            ("b", b"beta-image-bytes" * 7),
            ("c", b"gamma-image-bytes" * 2)]
    cfg = _multi_image_config(tmp_path, data)
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    for i, (_, entry_bytes) in enumerate(_toc_entries(payload, len(data))):
        f = _entry_fields(entry_bytes)
        image_bytes = payload[f["offset"] : f["offset"] + f["length"]]
        assert hashlib.sha256(image_bytes).digest() == f["hash"][:32]
        # Tail of the 64-byte hash field is 0x00 (unused, SHA-256 is 32 bytes).
        assert f["hash"][32:] == b"\x00" * 32
        # Length matches the source bytes the test wrote.
        assert image_bytes == data[i][1]


# ---------------------------------------------------------------------------
# Full Payload TOC entry layout
#
# The producer once emitted `hash` at entry offset 44 — the spec's
# security_version slot — truncating security_version, load_addr, entry_point,
# target_chiplet_id, and description into zero padding. A consumer reading the
# spec layout saw zeros where the digest belongs. These tests pin every field
# to its spec offset so that layout cannot drift back.
# ---------------------------------------------------------------------------


def test_entry_layout_covers_exactly_276_bytes():
    """The spec layout this suite asserts against is contiguous, gap-free, and
    exactly one TOC entry long — so 'every field is at its offset' also means
    'every byte of the entry is accounted for'."""
    spans = sorted(_SPEC_ENTRY_LAYOUT.values())
    cursor = 0
    for off, size in spans:
        assert off == cursor, f"gap or overlap in the spec layout at offset {off}"
        cursor = off + size
    assert cursor == oca_consts.TOC_ENTRY_SIZE == 276


def test_hash_field_at_spec_offset_80(tmp_path):
    """`hash` lives at entry offset 80..144, NOT at 44."""
    image = b"hash-offset-probe" * 5
    cfg = _multi_image_config(tmp_path, [("a", image)])
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    _, entry = next(iter(_toc_entries(payload, 1)))

    digest = hashlib.sha256(image).digest()
    assert entry[80:112] == digest, "image digest must start at entry offset 80"
    assert entry[112:144] == b"\x00" * 32, "hash field pads to 64 bytes with 0x00"
    # The old (wrong) position must not carry the digest.
    assert entry[44:76] != digest, "digest must not appear at the legacy offset 44"


def test_unset_optional_fields_are_zero(tmp_path):
    """security_version / load_addr / entry_point / target_chiplet_id default to
    0 ("unused" per the spec) and the description field is all-zero — the slots
    the misplaced hash used to occupy are now genuinely zero."""
    cfg = _multi_image_config(tmp_path, [("a", b"Z" * 24)])
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    _, entry = next(iter(_toc_entries(payload, 1)))
    f = _entry_fields(entry)

    assert f["security_version"] == 0
    assert f["load_addr"] == 0
    assert f["entry_point"] == 0
    assert f["target_chiplet_id"] == 0
    assert f["description"] == b"\x00" * 128
    # Bytes 44..80 are the four u64 fields, all zero here.
    assert entry[44:76] == b"\x00" * 32


def test_entry_reserved_regions_are_zero(tmp_path):
    """The spec requires the Producer to zero every reserved byte in every TOC
    entry (76..80 and 272..276)."""
    cfg = _multi_image_config(tmp_path, [("a", b"R" * 16), ("b", b"S" * 32)],
                              extra={"load_addr": 0xDEADBEEF, "description": "res"})
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    for _, entry in _toc_entries(payload, 2):
        assert _entry_raw(entry, "reserved_1") == b"\x00" * 4
        assert _entry_raw(entry, "reserved_2") == b"\x00" * 4


def test_optional_fields_round_trip_at_spec_offsets(tmp_path):
    """Every Table-6 field the config can set lands at its spec offset with the
    configured value."""
    values = {
        "security_version": 0x0000_0000_0000_00FF,
        "load_addr": 0x1000_0000_8000_0000,
        "entry_point": 0x0000_0000_0000_0040,
        "target_chiplet_id": 0xFEED_FACE_CAFE_BEEF,
        "description": "BLSTAGE1 for SEP ROM, release 2.1",
    }
    cfg = _multi_image_config(tmp_path, [("a", b"payload-a" * 3)], extra=values)
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    _, entry = next(iter(_toc_entries(payload, 1)))
    f = _entry_fields(entry)

    assert f["security_version"] == values["security_version"]
    assert f["load_addr"] == values["load_addr"]
    assert f["entry_point"] == values["entry_point"]
    assert f["target_chiplet_id"] == values["target_chiplet_id"]

    desc = _entry_raw(entry, "description")
    assert desc[: len(values["description"])] == values["description"].encode("ascii")
    assert desc[len(values["description"]) :] == b"\x00" * (128 - len(values["description"]))
    # Setting the new fields must not disturb the digest at offset 80.
    assert entry[80:112] == hashlib.sha256(b"payload-a" * 3).digest()


def test_optional_fields_are_per_image(tmp_path):
    """Each image carries its own load_addr / entry_point — the SEP ROM's BL1
    placement contract needs per-image values, not a payload-wide one."""
    cfg = _multi_image_config(tmp_path, [("a", b"A" * 16), ("b", b"B" * 16)])
    cfg["payload_images"][0]["load_addr"] = 0x8000_0000
    cfg["payload_images"][0]["entry_point"] = 0x100
    cfg["payload_images"][1]["load_addr"] = 0x9000_0000
    cfg["payload_images"][1]["entry_point"] = 0x200
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    entries = [_entry_fields(e) for _, e in _toc_entries(payload, 2)]

    by_load_addr = {e["load_addr"]: e["entry_point"] for e in entries}
    assert by_load_addr == {0x8000_0000: 0x100, 0x9000_0000: 0x200}


def test_description_terminating_nul_reserved(tmp_path):
    """127 chars fit; the 128th byte stays NUL. 128 chars is rejected."""
    cfg = _multi_image_config(tmp_path, [("a", b"D" * 8)],
                              extra={"description": "x" * 127})
    _, payload = _split_bundle(pack_oca_bundle(cfg))
    _, entry = next(iter(_toc_entries(payload, 1)))
    desc = _entry_raw(entry, "description")
    assert desc[:127] == b"x" * 127
    assert desc[127] == 0x00

    too_long = _multi_image_config(tmp_path, [("a", b"D" * 8)],
                                   extra={"description": "x" * 128})
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(too_long)
    assert exc.value.field_name == "payload_images"
    assert "127" in str(exc.value)


def test_description_non_ascii_rejected(tmp_path):
    cfg = _multi_image_config(tmp_path, [("a", b"D" * 8)],
                              extra={"description": "imagé"})
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"
    assert "ASCII" in str(exc.value)


@pytest.mark.parametrize(
    "field",
    ["security_version", "load_addr", "entry_point", "target_chiplet_id"],
)
def test_u64_entry_field_bounds(tmp_path, field):
    """Each u64 entry field accepts its maximum and rejects one past it."""
    at_max = _multi_image_config(tmp_path, [("a", b"U" * 8)],
                                 extra={field: (1 << 64) - 1})
    _, payload = _split_bundle(pack_oca_bundle(at_max))
    _, entry = next(iter(_toc_entries(payload, 1)))
    assert _entry_fields(entry)[field] == (1 << 64) - 1

    for bad in (1 << 64, -1):
        cfg = _multi_image_config(tmp_path, [("a", b"U" * 8)], extra={field: bad})
        with pytest.raises(OcaConfigError) as exc:
            pack_oca_bundle(cfg)
        assert exc.value.field_name == "payload_images"
        assert field in str(exc.value)


@pytest.mark.parametrize(
    "field",
    ["security_version", "load_addr", "entry_point", "target_chiplet_id"],
)
def test_u64_entry_field_rejects_non_integer(tmp_path, field):
    cfg = _multi_image_config(tmp_path, [("a", b"U" * 8)], extra={field: "not-a-number"})
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"
    assert field in str(exc.value)


def test_payload_hash_covers_toc_region(tmp_path):
    data = [("a", b"X" * 16), ("b", b"Y" * 16), ("c", b"Z" * 16)]
    cfg = _multi_image_config(tmp_path, data)
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    toc_byte_count = oca_consts.TOC_HEADER_SIZE + 3 * oca_consts.TOC_ENTRY_SIZE
    expected = hashlib.sha256(payload[:toc_byte_count]).digest()
    embedded = manifest[oca_consts.OFF_PAYLOAD_HASH : oca_consts.OFF_PAYLOAD_HASH + 32]
    assert embedded == expected


def test_payload_hash_chain_iterative_construction(tmp_path):
    data = [("a", b"chain-image-1" * 3),
            ("b", b"chain-image-2" * 4),
            ("c", b"chain-image-3" * 5)]
    cfg = _multi_image_config(tmp_path, data)
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    toc_byte_count = oca_consts.TOC_HEADER_SIZE + 3 * oca_consts.TOC_ENTRY_SIZE
    # H_0 = SHA-256(TOC)
    h = hashlib.sha256(payload[:toc_byte_count]).digest()
    # H_i = SHA-256(H_{i-1} || SHA-256(ENTRY_i_bytes)) for each TOC entry in order.
    for _, entry_bytes in _toc_entries(payload, 3):
        f = _entry_fields(entry_bytes)
        img = payload[f["offset"] : f["offset"] + f["length"]]
        h = hashlib.sha256(h + hashlib.sha256(img).digest()).digest()
    embedded = manifest[oca_consts.OFF_PAYLOAD_HASH_CHAIN : oca_consts.OFF_PAYLOAD_HASH_CHAIN + 32]
    assert embedded == h
    # Tail bytes 32..64 of the hash_chain field are 0x00.
    assert manifest[oca_consts.OFF_PAYLOAD_HASH_CHAIN + 32 : oca_consts.OFF_PAYLOAD_HASH_CHAIN + 64] == b"\x00" * 32


def test_image_count_zero_rejected(tmp_path):
    cfg = _multi_image_config(tmp_path, [("a", b"X")])  # placeholder for type info
    cfg["payload_images"] = []  # but actually no images
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "payload_images"


# Single-image case still works through the multi-image pipeline — a
# regression guard against breaking the single-image-baseline path.
def test_single_image_still_works_via_multi_pipeline(tmp_path):
    cfg = _multi_image_config(tmp_path, [("only", b"\xAA" * 32)])
    bundle = pack_oca_bundle(cfg)
    manifest, payload = _split_bundle(bundle)
    image_count = struct.unpack_from("<Q", payload, 16)[0]
    assert image_count == 1
    # Manifest body is still exactly 4096 bytes.
    assert len(manifest) == oca_consts.OCA_CLASSIC_BODY_SIZE

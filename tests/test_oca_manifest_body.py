"""Byte-correctness tests for the OCA-classic manifest body.

These tests build a bundle from a minimal in-memory config and assert
byte-level invariants of the 4096-byte manifest header — magic, length,
reserved regions, identity-byte fill, manifest_hash recomputation, and the
secure-boot zero-out behavior.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import struct

import pytest

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_config(tmp_path):
    """Smallest valid OCA-classic config: non-secure-boot, one image."""
    img = tmp_path / "img1.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF\x90\x90\x90\x90")  # 8 bytes
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "DEMO1",
        "description": "minimal oca-classic test",
        "secure_boot": 0,
        "timestamp": 1764633600,  # explicit for determinism
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [
            {"type": "DEMO1_X_BLSTAGE1", "path": str(img)},
        ],
    }


def _generate(config):
    """Run the OCA entry and return the bundle bytes (manifest + payload)."""
    return pack_oca_bundle(config)


def _manifest_body(bundle_bytes):
    """First 4096 bytes are the manifest body."""
    assert len(bundle_bytes) >= oca_consts.OCA_CLASSIC_BODY_SIZE
    return bundle_bytes[: oca_consts.OCA_CLASSIC_BODY_SIZE]


def test_body_is_exactly_4096_bytes(minimal_config):
    body = _manifest_body(_generate(minimal_config))
    assert len(body) == 4096


def test_magic_at_offset_zero_is_ocac(minimal_config):
    body = _manifest_body(_generate(minimal_config))
    assert body[0:4] == b"OCAC"


def test_classic_trailer_closes_the_signed_region(minimal_config):
    body = _manifest_body(_generate(minimal_config))
    start = oca_consts.OFF_CLASSIC_MANIFEST_TRAILER
    assert body[start:start + 4] == b"\xCA\xCA\xCA\xCA"
    # The trailer ends exactly where the signed region does.
    assert start + 4 == oca_consts.OCA_CLASSIC_SIGNED_REGION_END


# (offset, length) pairs of every "reserved" or "Must be 0x00" region of the
# 4096-byte body.
RESERVED_REGIONS = [
    (oca_consts.OFF_RESERVED_1, oca_consts.LEN_RESERVED_1),
    (oca_consts.OFF_RESERVED_2, oca_consts.LEN_RESERVED_2),
    (oca_consts.OFF_RESERVED_3, oca_consts.LEN_RESERVED_3),
    (oca_consts.OFF_RESERVED_4, oca_consts.LEN_RESERVED_4),
    (oca_consts.OFF_RESERVED_5, oca_consts.LEN_RESERVED_5),
    (oca_consts.OFF_RESERVED_6, oca_consts.LEN_RESERVED_6),
    (oca_consts.OFF_RESERVED_7, oca_consts.LEN_RESERVED_7),
    (oca_consts.OFF_RESERVED_8, oca_consts.LEN_RESERVED_8),
    (oca_consts.OFF_RESERVED_9, oca_consts.LEN_RESERVED_9),
    (oca_consts.OFF_RESERVED_10, oca_consts.LEN_RESERVED_10),
    (oca_consts.OFF_RESERVED_11, oca_consts.LEN_RESERVED_11),
    (oca_consts.OFF_RESERVED_12, oca_consts.LEN_RESERVED_12),
    (oca_consts.OFF_RESERVED_13, oca_consts.LEN_RESERVED_13),
    (oca_consts.OFF_RESERVED_14, oca_consts.LEN_RESERVED_14),
    (oca_consts.OFF_RESERVED_15, oca_consts.LEN_RESERVED_15),
    (oca_consts.OFF_RESERVED_16, oca_consts.LEN_RESERVED_16),
    (oca_consts.OFF_RESERVED_17, oca_consts.LEN_RESERVED_17),
    (oca_consts.OFF_RESERVED_18, oca_consts.LEN_RESERVED_18),
    (oca_consts.OFF_RESERVED_19, oca_consts.LEN_RESERVED_19),
    (oca_consts.OFF_RESERVED_20, oca_consts.LEN_RESERVED_20),
    (oca_consts.OFF_RESERVED_21, oca_consts.LEN_RESERVED_21),
    (oca_consts.OFF_RESERVED_22, oca_consts.LEN_RESERVED_22),
    (oca_consts.OFF_RESERVED_23, oca_consts.LEN_RESERVED_23),
]


def test_all_reserved_regions_are_zero(minimal_config):
    body = _manifest_body(_generate(minimal_config))
    for off, ln in RESERVED_REGIONS:
        region = body[off : off + ln]
        assert region == b"\x00" * ln, (
            f"Reserved region at offset {off}, length {ln} is not all-zero: "
            f"first non-zero byte at +{next((i for i, b in enumerate(region) if b != 0), None)}"
        )


def test_unselected_identity_bytes_are_a5(minimal_config):
    # No selector_bits set → all bytes of chiplet_id/package_id/system_id are
    # "unselected" → must all be 0xA5.
    body = _manifest_body(_generate(minimal_config))
    assert body[oca_consts.OFF_CHIPLET_ID : oca_consts.OFF_CHIPLET_ID + oca_consts.CHIPLET_ID_SIZE] == b"\xA5" * 32
    assert body[oca_consts.OFF_PACKAGE_ID : oca_consts.OFF_PACKAGE_ID + oca_consts.PACKAGE_ID_SIZE] == b"\xA5" * 32
    assert body[oca_consts.OFF_SYSTEM_ID : oca_consts.OFF_SYSTEM_ID + oca_consts.SYSTEM_ID_SIZE] == b"\xA5" * 32


def test_partial_selector_marks_only_selected_bytes(minimal_config, tmp_path):
    # Set selector_bits so byte 0 of chiplet_id is selected; all other identity
    # bytes (and all bits 8+ for chiplet_id) remain unselected.
    minimal_config["usage_constraints"] = {
        "selector_bits": 0x1,  # bit 0 → chiplet_id byte 0
        "chiplet_id": bytes([0x7C] + [0x00] * 31).hex(),  # selected byte = 0x7C
    }
    body = _manifest_body(_generate(minimal_config))
    # Selected byte 0 has user value 0x7C
    assert body[oca_consts.OFF_CHIPLET_ID] == 0x7C
    # Bytes 1..31 are unselected → 0xA5
    assert body[oca_consts.OFF_CHIPLET_ID + 1 : oca_consts.OFF_CHIPLET_ID + 32] == b"\xA5" * 31


def test_manifest_hash_independently_recomputes(minimal_config):
    body = _manifest_body(_generate(minimal_config))
    signed_region = body[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]  # bytes [0, 3145)
    expected = hashlib.sha256(signed_region).digest()
    embedded_hash = body[oca_consts.OFF_MANIFEST_HASH : oca_consts.OFF_MANIFEST_HASH + oca_consts.MANIFEST_HASH_DIGEST_SIZE]
    assert embedded_hash == expected
    # Trailing bytes of the 64-byte field are 0x00 (unused).
    assert body[
        oca_consts.OFF_MANIFEST_HASH + oca_consts.MANIFEST_HASH_DIGEST_SIZE : oca_consts.OFF_MANIFEST_HASH + oca_consts.HASH_FIELD_SIZE
    ] == b"\x00" * 32


def test_manifest_identifier_ascii_padding(minimal_config):
    minimal_config["manifest_identifier"] = "X"
    body = _manifest_body(_generate(minimal_config))
    assert body[oca_consts.OFF_MANIFEST_IDENTIFIER : oca_consts.OFF_MANIFEST_IDENTIFIER + 8] == b"X\x00\x00\x00\x00\x00\x00\x00"


def test_manifest_identifier_full_eight_chars(minimal_config):
    minimal_config["manifest_identifier"] = "ABCDEFGH"
    body = _manifest_body(_generate(minimal_config))
    assert body[oca_consts.OFF_MANIFEST_IDENTIFIER : oca_consts.OFF_MANIFEST_IDENTIFIER + 8] == b"ABCDEFGH"


def test_description_nul_terminated_at_byte_127(minimal_config):
    minimal_config["description"] = "x" * 64  # arbitrary length under the cap
    body = _manifest_body(_generate(minimal_config))
    # The full 128-byte field is at OFF_MANIFEST_DESCRIPTION..+128; byte 127 must be NUL.
    assert body[oca_consts.OFF_MANIFEST_DESCRIPTION + 127] == 0


def test_secure_boot_disabled_zeroes_signature_fields(minimal_config):
    # Carry signature-related keys in the config to ensure they're explicitly
    # zeroed in the output (not leaked from the input config).
    minimal_config["secure_boot"] = 0
    minimal_config["signature_type"] = 0x01
    minimal_config["public_key_select_classic"] = 0xABCD
    body = _manifest_body(_generate(minimal_config))

    # signature_classic (512 bytes)
    assert body[oca_consts.OFF_SIGNATURE_CLASSIC : oca_consts.OFF_SIGNATURE_CLASSIC + oca_consts.SIGNATURE_CLASSIC_SIZE] == b"\x00" * 512
    # public_key_classic
    assert body[oca_consts.OFF_PUBLIC_KEY_CLASSIC : oca_consts.OFF_PUBLIC_KEY_CLASSIC + oca_consts.PUBLIC_KEY_CLASSIC_SIZE] == b"\x00" * oca_consts.PUBLIC_KEY_CLASSIC_SIZE
    # public_key_select_classic (16 bytes) — config value MUST NOT leak
    assert body[oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC : oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC + 16] == b"\x00" * 16
    # Single-byte secure-boot-gated fields
    assert body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC] == 0
    assert body[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC] == 0
    assert body[oca_consts.OFF_PUBLIC_KEY_ENCODING_CLASSIC] == 0


def test_timestamp_is_logged(minimal_config, caplog):
    # Run at INFO level (the entry should log timestamp at INFO so it's visible
    # in non-verbose runs too — verbose mode just lowers the threshold).
    minimal_config["timestamp"] = 1764633600
    with caplog.at_level(logging.INFO):
        body = _manifest_body(_generate(minimal_config))

    # Find at least one record whose message contains the literal "timestamp: 1764633600".
    matched = [r for r in caplog.records if re.search(r"\btimestamp:\s*1764633600\b", r.getMessage())]
    assert matched, (
        "No log record matched 'timestamp: 1764633600'. "
        f"All captured messages: {[r.getMessage() for r in caplog.records]}"
    )

    # Cross-check: the embedded timestamp byte field matches the logged value.
    embedded_ts = struct.unpack_from("<q", body, oca_consts.OFF_TIMESTAMP)[0]
    assert embedded_ts == 1764633600


# ---------------------------------------------------------------------------
# Per-byte chiplet_id config → manifest bytes integration.
# ---------------------------------------------------------------------------


def test_per_byte_chiplet_id_to_manifest_bytes(minimal_config):
    """Sparse per-byte chiplet_id ergonomic input produces the expected
    manifest bytes (chiplet_id field + selector_bits region)."""
    minimal_config["usage_constraints"] = {"chiplet_id": {0: 0xDE, 1: 0xAD}}
    body = _manifest_body(_generate(minimal_config))

    # chiplet_id bytes 40..71: 0xDE, 0xAD, then 0xA5 × 30.
    assert body[oca_consts.OFF_CHIPLET_ID : oca_consts.OFF_CHIPLET_ID + 2] == b"\xDE\xAD"
    assert body[oca_consts.OFF_CHIPLET_ID + 2 : oca_consts.OFF_CHIPLET_ID + 32] == b"\xA5" * 30

    # selector_bits region (offset 24, 16 bytes little-endian). Bits 0 and 1
    # set → byte 24 = 0x03, bytes 25..39 = 0x00.
    assert body[oca_consts.OFF_SELECTOR_BITS] == 0x03
    assert body[oca_consts.OFF_SELECTOR_BITS + 1 : oca_consts.OFF_SELECTOR_BITS + 16] == b"\x00" * 15


# ---------------------------------------------------------------------------
# Lifecycle named-list config → manifest bytes integration.
# ---------------------------------------------------------------------------


def test_lifecycle_states_to_manifest_bytes(minimal_config):
    """[TEST_DEV, PROD_END] for the chiplet level encodes to 0x05 at bytes
    136..140 and sets selector_bits bit 96 (low bit of byte 36)."""
    minimal_config["usage_constraints"] = {
        "lifecycle_chiplet_states": ["TEST_DEV", "PROD_END"],
    }
    body = _manifest_body(_generate(minimal_config))

    # lifecycle_chiplet_states bytes 136..140 little-endian = 0x05 0x00 0x00 0x00.
    assert (
        body[oca_consts.OFF_LIFECYCLE_CHIPLET_STATES : oca_consts.OFF_LIFECYCLE_CHIPLET_STATES + 4]
        == b"\x05\x00\x00\x00"
    )
    # selector_bits byte 12 holds bits 96..103. Bit 96 alone → 0x01.
    # bytes 13..15 (bits 104..127) are zero.
    assert body[oca_consts.OFF_SELECTOR_BITS + 12] == 0x01
    assert body[oca_consts.OFF_SELECTOR_BITS + 13 : oca_consts.OFF_SELECTOR_BITS + 16] == b"\x00" * 3


# ---------------------------------------------------------------------------
# Version-range fields: 8 bytes per level encoding (minor_min, major_min,
# minor_max, major_max) as LE u16s, with enable bits in selector_bits[99..104].
# ---------------------------------------------------------------------------


def test_version_range_to_manifest_bytes(minimal_config):
    """Three levels exercised: chiplet has both halves, package has min only,
    system has max only. Enable bits 99, 100, 101, 104 are set (bits 102, 103
    stay clear because package_max and system_min are absent)."""
    minimal_config["usage_constraints"] = {
        "version_range_chiplet": {
            "major_min": 1, "minor_min": 0, "major_max": 2, "minor_max": 255,
        },
        "version_range_package": {"major_min": 3, "minor_min": 4},
        "version_range_system":  {"major_max": 5, "minor_max": 6},
    }
    body = _manifest_body(_generate(minimal_config))

    assert (
        body[oca_consts.OFF_VERSION_RANGE_CHIPLET : oca_consts.OFF_VERSION_RANGE_CHIPLET + 8]
        == b"\x00\x00\x01\x00\xFF\x00\x02\x00"
    )
    assert (
        body[oca_consts.OFF_VERSION_RANGE_PACKAGE : oca_consts.OFF_VERSION_RANGE_PACKAGE + 8]
        == b"\x04\x00\x03\x00\x00\x00\x00\x00"
    )
    assert (
        body[oca_consts.OFF_VERSION_RANGE_SYSTEM : oca_consts.OFF_VERSION_RANGE_SYSTEM + 8]
        == b"\x00\x00\x00\x00\x06\x00\x05\x00"
    )

    # selector_bits byte 12 = bits 96..103. Bits 99, 100, 101 set → 0x38;
    # bit 104 (byte 13, bit 0) set → 0x01. Bytes 14..15 zero.
    assert body[oca_consts.OFF_SELECTOR_BITS + 12] == 0x38
    assert body[oca_consts.OFF_SELECTOR_BITS + 13] == 0x01
    assert body[oca_consts.OFF_SELECTOR_BITS + 14 : oca_consts.OFF_SELECTOR_BITS + 16] == b"\x00\x00"


# ---------------------------------------------------------------------------
# Demotion-control: 2 bytes at offset 172, LE u16 with vendor-defined bits.
# ---------------------------------------------------------------------------


def test_demotion_control_raw_int_to_manifest_bytes(minimal_config):
    """Raw integer form lands as a LE u16 at the demotion_control offset."""
    minimal_config["usage_constraints"] = {"demotion_control": 0x0001}
    body = _manifest_body(_generate(minimal_config))
    assert body[oca_consts.OFF_DEMOTION_CONTROL : oca_consts.OFF_DEMOTION_CONTROL + 2] == b"\x01\x00"


def test_demotion_control_named_flags_to_manifest_bytes(minimal_config):
    """Named-flag form (BL1_DEMOTION_VALID + BL2_DEMOTION_ENABLE → bits 0 and 3
    → 0x09) encodes to the same 2-byte LE u16 representation."""
    minimal_config["usage_constraints"] = {
        "demotion_control": ["BL1_DEMOTION_VALID", "BL2_DEMOTION_ENABLE"],
    }
    body = _manifest_body(_generate(minimal_config))
    assert body[oca_consts.OFF_DEMOTION_CONTROL : oca_consts.OFF_DEMOTION_CONTROL + 2] == b"\x09\x00"

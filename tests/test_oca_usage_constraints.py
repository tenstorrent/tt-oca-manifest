"""Unit tests for the OCA-classic usage-constraints decoder.

Covers selector_bits derivation for per-byte identity selection, lifecycle
named-state lists, version-range halves, and demotion control.
"""

from __future__ import annotations

import pytest

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.usage_constraints import decode
from tt_boot_manifest.oca.validators import OcaConfigError


# ---------------------------------------------------------------------------
# Per-byte identity selection: sparse mapping and dense + selection forms.
# ---------------------------------------------------------------------------


def test_sparse_mapping_chiplet_id_decodes():
    """Sparse mapping decodes to active bytes + 0xA5 fill, with selector_bits
    matching the active byte indices."""
    out = decode({"chiplet_id": {0: 0xDE, 1: 0xAD}}, secure_boot=0)
    assert out["chiplet_id_bytes"][:2] == b"\xDE\xAD"
    assert out["chiplet_id_bytes"][2:] == b"\xA5" * 30
    # Bits 0 and 1 set, nothing else in bits[31:0].
    assert out["selector_bits"] & 0xFFFFFFFF == 0b11


def test_dense_value_plus_selected_list():
    """Dense `value` + `selected` list matches the sparse form byte-for-byte."""
    sparse = decode({"chiplet_id": {0: 0xDE, 1: 0xAD}}, secure_boot=0)
    dense = decode(
        {"chiplet_id": {"value": [0xDE, 0xAD] + [0xA5] * 30, "selected": [0, 1]}},
        secure_boot=0,
    )
    assert dense["chiplet_id_bytes"] == sparse["chiplet_id_bytes"]
    assert dense["selector_bits"] == sparse["selector_bits"]


def test_dense_value_plus_mask_int():
    """Dense `value` + `mask` integer matches the sparse form byte-for-byte."""
    sparse = decode({"chiplet_id": {0: 0xDE, 1: 0xAD}}, secure_boot=0)
    dense = decode(
        {"chiplet_id": {"value": [0xDE, 0xAD] + [0xA5] * 30, "mask": 0x3}},
        secure_boot=0,
    )
    assert dense["chiplet_id_bytes"] == sparse["chiplet_id_bytes"]
    assert dense["selector_bits"] == sparse["selector_bits"]


def test_explicit_a5_vs_omitted_equivalent():
    """Explicit 0xA5 at an unselected byte and an omitted byte produce
    byte-identical normalized output."""
    sparse = decode({"chiplet_id": {0: 0xDE}}, secure_boot=0)
    dense_explicit_a5 = decode(
        {"chiplet_id": {"value": [0xDE] + [0xA5] * 31, "selected": [0]}},
        secure_boot=0,
    )
    assert dense_explicit_a5["chiplet_id_bytes"] == sparse["chiplet_id_bytes"]
    assert dense_explicit_a5["selector_bits"] == sparse["selector_bits"]


def test_dense_non_a5_at_unselected_rejected():
    """Non-0xA5 byte at an unselected index in the dense form is rejected
    with a single-line error naming the field and offending indices."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode(
            {"chiplet_id": {"value": [0xDE, 0xAD, 0xFF] + [0xA5] * 29, "selected": [0, 1]}},
            secure_boot=0,
        )
    assert excinfo.value.field_name == "chiplet_id"
    assert "2" in str(excinfo.value)  # byte index 2 is the offender


@pytest.mark.parametrize(
    "field_name, expected_bit_offset",
    [("chiplet_id", 0), ("package_id", 32), ("system_id", 64)],
)
def test_id_selector_bit_offsets(field_name, expected_bit_offset):
    """Selecting byte 0 of each ID field sets the corresponding selector bit
    in the right region of selector_bits."""
    out = decode({field_name: {0: 0x55}}, secure_boot=0)
    assert (out["selector_bits"] >> expected_bit_offset) & 1 == 1
    # And nothing outside that one bit:
    assert out["selector_bits"] == (1 << expected_bit_offset)


@pytest.mark.parametrize("bad", [256, -1, 0x1000])
def test_id_byte_value_out_of_range_rejected(bad):
    """Out-of-range byte values are rejected naming the field."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"chiplet_id": {5: bad}}, secure_boot=0)
    assert excinfo.value.field_name == "chiplet_id"


# ---------------------------------------------------------------------------
# Lifecycle named-state lists.
# ---------------------------------------------------------------------------


def test_lifecycle_named_list_decodes():
    """Named-list form decodes to OR'd bit values and sets the enable bit."""
    out = decode(
        {"lifecycle_chiplet_states": ["TEST_DEV", "PROD_END"]}, secure_boot=0
    )
    # TEST_DEV → bit 0, PROD_END → bit 2 ⇒ 0b101 = 0x05.
    assert out["lifecycle_chiplet_states"] == 0x05
    # Enable bit 96 set; nothing else.
    assert out["selector_bits"] == (1 << 96)


def test_lifecycle_raw_integer_form():
    """Raw integer form passes through and sets the enable bit."""
    out = decode({"lifecycle_chiplet_states": 0x05}, secure_boot=0)
    assert out["lifecycle_chiplet_states"] == 0x05
    assert out["selector_bits"] == (1 << 96)


def test_lifecycle_empty_list_equivalent_to_absent():
    """Empty list and absence both produce 0 and leave the enable bit clear."""
    out_empty = decode({"lifecycle_chiplet_states": []}, secure_boot=0)
    out_absent = decode({}, secure_boot=0)
    assert out_empty["lifecycle_chiplet_states"] == 0
    assert out_absent["lifecycle_chiplet_states"] == 0
    assert (out_empty["selector_bits"] >> 96) & 1 == 0
    assert (out_absent["selector_bits"] >> 96) & 1 == 0


def test_lifecycle_unknown_name_rejected():
    """Unknown token raises naming both the bad name and the supported set."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"lifecycle_chiplet_states": ["BANANA"]}, secure_boot=0)
    assert excinfo.value.field_name == "lifecycle_chiplet_states"
    msg = str(excinfo.value)
    assert "BANANA" in msg
    assert "TEST_DEV" in msg  # supported set is enumerated in the message


@pytest.mark.parametrize("bad", [0x80, 0x100, 0xFFFFFFFF])
def test_lifecycle_raw_reserved_bits_rejected(bad):
    """Raw integer with any bit set in 7..31 is rejected naming the reserved
    range."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"lifecycle_chiplet_states": bad}, secure_boot=0)
    assert excinfo.value.field_name == "lifecycle_chiplet_states"
    assert "7" in str(excinfo.value) or "reserved" in str(excinfo.value).lower()


def test_lifecycle_rma_sop_rejected_in_oca_classic():
    """The legacy `RMA_SoP` spelling is rejected with a hint pointing to the
    OCA-classic name `RMA_SIP`."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"lifecycle_chiplet_states": ["RMA_SoP"]}, secure_boot=0)
    assert excinfo.value.field_name == "lifecycle_chiplet_states"
    assert "RMA_SIP" in str(excinfo.value)


@pytest.mark.parametrize(
    "field, expected_bit",
    [
        ("lifecycle_chiplet_states", 96),
        ("lifecycle_package_states", 97),
        ("lifecycle_system_states", 98),
    ],
)
def test_lifecycle_selector_bits_per_level(field, expected_bit):
    """Each lifecycle level independently sets its own enable bit."""
    out = decode({field: ["TEST_DEV"]}, secure_boot=0)
    assert (out["selector_bits"] >> expected_bit) & 1 == 1
    assert out["selector_bits"] == (1 << expected_bit)


def test_lifecycle_multi_state_or_semantics():
    """Multi-state lists OR the per-token bit values."""
    # TEST_DEV (bit 0) | PROD (bit 1) | RMA_CHIPLET (bit 4) = 0b00010011 = 0x13.
    out = decode(
        {"lifecycle_chiplet_states": ["TEST_DEV", "PROD", "RMA_CHIPLET"]},
        secure_boot=0,
    )
    assert out["lifecycle_chiplet_states"] == 0x13


# ---------------------------------------------------------------------------
# Version-range halves: independently-optional min / max per level, packed
# into 8 bytes as (minor_min, major_min, minor_max, major_max) LE u16s.
# ---------------------------------------------------------------------------


def test_version_range_both_halves_specified():
    """Both halves present → all 8 bytes populated, both enable bits set."""
    out = decode(
        {"version_range_chiplet": {
            "major_min": 1, "minor_min": 0, "major_max": 2, "minor_max": 255,
        }},
        secure_boot=0,
    )
    assert out["version_range_chiplet_bytes"] == b"\x00\x00\x01\x00\xFF\x00\x02\x00"
    assert (out["selector_bits"] >> 99) & 1 == 1
    assert (out["selector_bits"] >> 100) & 1 == 1


def test_version_range_min_half_only():
    """Only the min half is specified → max bytes are zero, only min enable bit set."""
    out = decode(
        {"version_range_chiplet": {"major_min": 1, "minor_min": 0}},
        secure_boot=0,
    )
    assert out["version_range_chiplet_bytes"] == b"\x00\x00\x01\x00\x00\x00\x00\x00"
    assert (out["selector_bits"] >> 99) & 1 == 1
    assert (out["selector_bits"] >> 100) & 1 == 0


def test_version_range_max_half_only():
    """Only the max half is specified → min bytes are zero, only max enable bit set."""
    out = decode(
        {"version_range_chiplet": {"major_max": 2, "minor_max": 255}},
        secure_boot=0,
    )
    assert out["version_range_chiplet_bytes"] == b"\x00\x00\x00\x00\xFF\x00\x02\x00"
    assert (out["selector_bits"] >> 99) & 1 == 0
    assert (out["selector_bits"] >> 100) & 1 == 1


def test_version_range_absent_level_zero_bytes():
    """An omitted level decodes to 8 zero bytes with both enable bits clear."""
    out = decode({}, secure_boot=0)
    assert out["version_range_package_bytes"] == b"\x00" * 8
    assert (out["selector_bits"] >> 101) & 1 == 0
    assert (out["selector_bits"] >> 102) & 1 == 0


def test_version_range_partial_half_default_zero():
    """A half is 'specified' if any of its two keys is present; missing keys
    default to 0 but the enable bit still sets."""
    out = decode(
        {"version_range_chiplet": {"major_min": 1}},  # no minor_min key
        secure_boot=0,
    )
    # minor_min defaults to 0; major_min=1; max half is absent.
    assert out["version_range_chiplet_bytes"] == b"\x00\x00\x01\x00\x00\x00\x00\x00"
    assert (out["selector_bits"] >> 99) & 1 == 1
    assert (out["selector_bits"] >> 100) & 1 == 0


@pytest.mark.parametrize(
    "inverted",
    [
        {"major_min": 2, "major_max": 1},
        {"major_min": 1, "minor_min": 10, "major_max": 1, "minor_max": 5},
    ],
)
def test_version_range_inverted_rejected(inverted):
    """When both halves are specified, (major_min, minor_min) must be ≤
    (major_max, minor_max) lexicographically."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"version_range_chiplet": inverted}, secure_boot=0)
    assert excinfo.value.field_name == "version_range_chiplet"


def test_version_range_overflow_rejected():
    """Each key must fit in 16 bits; 0x10000 is rejected."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode(
            {"version_range_chiplet": {"major_min": 0x10000}},
            secure_boot=0,
        )
    assert excinfo.value.field_name == "version_range_chiplet"
    assert "16" in str(excinfo.value)


@pytest.mark.parametrize(
    "field, half_key, expected_bit",
    [
        ("version_range_chiplet", "major_min", 99),
        ("version_range_chiplet", "major_max", 100),
        ("version_range_package", "major_min", 101),
        ("version_range_package", "major_max", 102),
        ("version_range_system",  "major_min", 103),
        ("version_range_system",  "major_max", 104),
    ],
)
def test_version_range_selector_bits_per_level(field, half_key, expected_bit):
    """Each (level, half) independently sets its own enable bit."""
    out = decode({field: {half_key: 1}}, secure_boot=0)
    assert (out["selector_bits"] >> expected_bit) & 1 == 1
    assert out["selector_bits"] == (1 << expected_bit)


# ---------------------------------------------------------------------------
# Demotion-control: 16-bit field with vendor-defined bits
#   0 BL1_DEMOTION_VALID, 1 BL1_DEMOTION_ENABLE,
#   2 BL2_DEMOTION_VALID, 3 BL2_DEMOTION_ENABLE
# Bits 4..15 are unused and must be zero.
# ---------------------------------------------------------------------------


def test_demotion_control_int_passes_through():
    """Raw 16-bit integer passes through to the output dict."""
    out = decode({"demotion_control": 0x0001}, secure_boot=0)
    assert out["demotion_control"] == 1


def test_demotion_control_absent_defaults_to_zero():
    """Omitted field decodes to 0."""
    out = decode({}, secure_boot=0)
    assert out["demotion_control"] == 0


def test_demotion_control_overflow_rejected():
    """Values that don't fit in 16 bits are rejected."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"demotion_control": 0x10000}, secure_boot=0)
    assert excinfo.value.field_name == "demotion_control"
    assert "16" in str(excinfo.value)


@pytest.mark.parametrize("bad", [0x10, 0x20, 0x8000, 0xFFF0])
def test_demotion_control_raw_reserved_bits_rejected(bad):
    """Raw integers with any bit in 4..15 set are rejected with the
    reserved-range message."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"demotion_control": bad}, secure_boot=0)
    assert excinfo.value.field_name == "demotion_control"
    assert "reserved" in str(excinfo.value).lower() or "4" in str(excinfo.value)


def test_demotion_control_named_flags_decode():
    """Named-flag list OR's the bit values: BL1_DEMOTION_VALID (bit 0) and
    BL1_DEMOTION_ENABLE (bit 1) → 0b11 = 0x3."""
    out = decode(
        {"demotion_control": ["BL1_DEMOTION_VALID", "BL1_DEMOTION_ENABLE"]},
        secure_boot=0,
    )
    assert out["demotion_control"] == 0x3


def test_demotion_control_named_flags_all_set():
    """All four flags together OR to 0xF."""
    out = decode(
        {"demotion_control": [
            "BL1_DEMOTION_VALID", "BL1_DEMOTION_ENABLE",
            "BL2_DEMOTION_VALID", "BL2_DEMOTION_ENABLE",
        ]},
        secure_boot=0,
    )
    assert out["demotion_control"] == 0xF


def test_demotion_control_empty_list_zero():
    """Empty list and absent field both decode to 0."""
    out = decode({"demotion_control": []}, secure_boot=0)
    assert out["demotion_control"] == 0


def test_demotion_control_unknown_flag_rejected():
    """Unknown flag name raises naming both the bad token and the supported set."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"demotion_control": ["BANANA_FLAG"]}, secure_boot=0)
    assert excinfo.value.field_name == "demotion_control"
    msg = str(excinfo.value)
    assert "BANANA_FLAG" in msg
    assert "BL1_DEMOTION_VALID" in msg  # supported set enumerated


# ---------------------------------------------------------------------------
# Mode-conflict diagnostics, reserved selector_bits, and shape errors.
# ---------------------------------------------------------------------------


def test_raw_and_ergonomic_mutually_exclusive():
    """Raw `selector_bits` plus an ergonomic-shaped field raises a single
    error naming both inputs and embedding the raw-equivalent that the
    ergonomic fields alone would have produced."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode(
            {"selector_bits": 0x05, "lifecycle_chiplet_states": ["TEST_DEV"]},
            secure_boot=0,
        )
    assert excinfo.value.field_name == "usage_constraints"
    msg = str(excinfo.value)
    # Both inputs are named.
    assert "selector_bits" in msg
    assert "lifecycle_chiplet_states" in msg
    # The raw-equivalent of [TEST_DEV] is "lifecycle_chiplet enable bit 96"
    # = 1 << 96 = 0x1000000000000000000000000.
    assert "0x1000000000000000000000000" in msg


def test_raw_and_dense_id_dict_mutually_exclusive():
    """A dict-shaped ID (ergonomic) alongside raw `selector_bits` is rejected;
    the legacy hex-string ID shape is still permitted (backward-compat)."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode(
            {"selector_bits": 0, "chiplet_id": {0: 0xDE}},
            secure_boot=0,
        )
    assert excinfo.value.field_name == "usage_constraints"
    msg = str(excinfo.value)
    assert "chiplet_id" in msg


def test_legacy_id_shape_with_selector_bits_still_works():
    """A hex-string ID alongside raw `selector_bits` is the legacy raw
    mode and must continue to decode successfully."""
    out = decode(
        {
            "selector_bits": 0x1,
            "chiplet_id": (bytes([0x7C]) + bytes(31)).hex(),
        },
        secure_boot=0,
    )
    # selector_bits[0] = 1 → byte 0 active (0x7C), rest of the field is 0xA5.
    assert out["chiplet_id_bytes"][0] == 0x7C
    assert out["chiplet_id_bytes"][1:] == b"\xA5" * 31
    assert out["selector_bits"] == 0x1


@pytest.mark.parametrize(
    "bad",
    [1 << 105, 1 << 127, (1 << 105) | (1 << 110), (1 << 128) - 1],
)
def test_raw_selector_bits_reserved_127_105_rejected(bad):
    """Any bit set in the reserved range 105..127 is rejected with a message
    that names the range."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode({"selector_bits": bad}, secure_boot=0)
    assert excinfo.value.field_name == "selector_bits"
    msg = str(excinfo.value)
    assert "105" in msg and "127" in msg


def test_id_hex_string_malformed_rejected():
    """Dense ID with a malformed hex string in `value` is rejected with a
    message that names the offending field and flags the malformed hex."""
    with pytest.raises(OcaConfigError) as excinfo:
        decode(
            {"chiplet_id": {"value": "ZZ" * 32, "selected": [0]}},
            secure_boot=0,
        )
    assert excinfo.value.field_name == "chiplet_id"
    assert "malformed" in str(excinfo.value).lower() or "hex" in str(excinfo.value).lower()

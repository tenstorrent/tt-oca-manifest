"""OCA-classic usage-constraints decoder.

Transforms the producer-supplied `usage_constraints` YAML block into the
normalized values the manifest builder consumes:

    selector_bits             : int (128-bit)
    chiplet_id_bytes          : bytes (32, unselected → 0xA5)
    package_id_bytes          : bytes (32, unselected → 0xA5)
    system_id_bytes           : bytes (32, unselected → 0xA5)
    lifecycle_chiplet_states  : int (32-bit)
    lifecycle_package_states  : int (32-bit)
    lifecycle_system_states   : int (32-bit)
    version_range_chiplet_bytes : bytes (8, OCA layout)
    version_range_package_bytes : bytes (8, OCA layout)
    version_range_system_bytes  : bytes (8, OCA layout)
    demotion_control          : int (16-bit)

Two input modes:
- **Raw**: producer supplies `selector_bits` directly. Identity, lifecycle,
  version-range, and demotion-control fields pass through in their integer /
  legacy-binary forms.
- **Ergonomic**: producer supplies high-level shapes (sparse byte mappings,
  named-token lists, version-range halves, named-flag lists);
  `selector_bits[0..104]` is auto-derived from the shapes.

Combining raw `selector_bits` with any ergonomic-shaped field is rejected
with a single-line error that embeds the raw-equivalent the ergonomic shapes
alone would have produced. The legacy hex-string identity form remains
compatible with raw `selector_bits` for backward compatibility.

Raises `oca.validators.OcaConfigError` on any validation failure.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Optional

from . import constants as oca_consts

__all__ = ["decode"]


def decode(usage_constraints_dict: Dict[str, Any], *, secure_boot: int) -> Dict[str, Any]:
    """Decode a `usage_constraints` block into the normalized output dict.

    See the module docstring for the output key set and the raw / ergonomic
    mode semantics.
    """
    from .validators import OcaConfigError  # deferred to avoid import cycle

    uc = usage_constraints_dict or {}

    # Mode-conflict detection: explicit `selector_bits` combined with any
    # ergonomic-shaped input is rejected with a single error embedding the
    # raw-equivalent of the ergonomic shapes.
    if "selector_bits" in uc:
        ergonomic_keys = _detect_ergonomic_keys(uc)
        if ergonomic_keys:
            uc_only_ergonomic = {k: v for k, v in uc.items() if k != "selector_bits"}
            equivalent = decode(uc_only_ergonomic, secure_boot=secure_boot)["selector_bits"]
            raise OcaConfigError(
                f"raw selector_bits cannot be combined with ergonomic fields "
                f"{ergonomic_keys}; the ergonomic fields alone would have "
                f"produced selector_bits = 0x{equivalent:X}",
                field_name="usage_constraints",
            )

    # selector_bits — 128-bit integer, default 0 (wildcard).
    # In raw mode the producer sets this directly; in ergonomic mode bits
    # [0..95] are OR'd in from the per-ID masks computed below.
    raw_selector_bits = int(uc.get("selector_bits", 0))
    if not (0 <= raw_selector_bits < (1 << 128)):
        raise OcaConfigError(
            f"selector_bits must fit in 128 bits; got {raw_selector_bits}",
            field_name="selector_bits",
        )
    if raw_selector_bits & oca_consts.SELECTOR_BITS_RESERVED_MASK:
        raise OcaConfigError(
            f"selector_bits 0x{raw_selector_bits:X} has reserved bits "
            f"105..127 set; only bits 0..104 are defined",
            field_name="selector_bits",
        )

    # chiplet_id / package_id / system_id — 32 bytes each; unselected → 0xA5.
    # Bit offsets within selector_bits:
    #   bit[31:0]  → chiplet_id bytes 0..31
    #   bit[63:32] → package_id bytes 0..31
    #   bit[95:64] → system_id  bytes 0..31
    chiplet_id_bytes, chiplet_id_mask = _decode_identity_field(
        uc.get("chiplet_id"), field_name="chiplet_id", bit_offset=0,
        raw_selector_bits=raw_selector_bits,
    )
    package_id_bytes, package_id_mask = _decode_identity_field(
        uc.get("package_id"), field_name="package_id", bit_offset=32,
        raw_selector_bits=raw_selector_bits,
    )
    system_id_bytes, system_id_mask = _decode_identity_field(
        uc.get("system_id"), field_name="system_id", bit_offset=64,
        raw_selector_bits=raw_selector_bits,
    )

    selector_bits = raw_selector_bits | chiplet_id_mask | package_id_mask | system_id_mask

    # Lifecycle states — accept named-token lists or raw integers; OR the
    # enable bit (96/97/98) into selector_bits when the producer specified a
    # non-empty list or non-zero int.
    lifecycle_chiplet_states, lc_chiplet_specified = _decode_lifecycle_field(
        uc.get("lifecycle_chiplet_states"), field_name="lifecycle_chiplet_states",
    )
    lifecycle_package_states, lc_package_specified = _decode_lifecycle_field(
        uc.get("lifecycle_package_states"), field_name="lifecycle_package_states",
    )
    lifecycle_system_states, lc_system_specified = _decode_lifecycle_field(
        uc.get("lifecycle_system_states"), field_name="lifecycle_system_states",
    )
    if lc_chiplet_specified:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_LIFECYCLE_CHIPLET
    if lc_package_specified:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_LIFECYCLE_PACKAGE
    if lc_system_specified:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_LIFECYCLE_SYSTEM

    # Version ranges — each level decodes to (8 bytes, min_specified,
    # max_specified). Enable bits (99..104) are OR'd into selector_bits per
    # specified half.
    version_range_chiplet_bytes, vr_chiplet_min, vr_chiplet_max = _decode_version_range_field(
        uc.get("version_range_chiplet"), field_name="version_range_chiplet",
    )
    version_range_package_bytes, vr_package_min, vr_package_max = _decode_version_range_field(
        uc.get("version_range_package"), field_name="version_range_package",
    )
    version_range_system_bytes, vr_system_min, vr_system_max = _decode_version_range_field(
        uc.get("version_range_system"), field_name="version_range_system",
    )
    if vr_chiplet_min:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_CHIPLET_MIN
    if vr_chiplet_max:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_CHIPLET_MAX
    if vr_package_min:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_PACKAGE_MIN
    if vr_package_max:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_PACKAGE_MAX
    if vr_system_min:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_SYSTEM_MIN
    if vr_system_max:
        selector_bits |= 1 << oca_consts.SELECTOR_BIT_VERSION_SYSTEM_MAX

    # demotion_control — 16-bit field accepting either a raw integer or a
    # list of named vendor flags (BL1_*/BL2_*); reserved bits 4..15 rejected.
    demotion_control = _decode_demotion_control(
        uc.get("demotion_control"), field_name="demotion_control",
    )

    return {
        "selector_bits": selector_bits,
        "chiplet_id_bytes": chiplet_id_bytes,
        "package_id_bytes": package_id_bytes,
        "system_id_bytes": system_id_bytes,
        "lifecycle_chiplet_states": lifecycle_chiplet_states,
        "lifecycle_package_states": lifecycle_package_states,
        "lifecycle_system_states": lifecycle_system_states,
        "version_range_chiplet_bytes": version_range_chiplet_bytes,
        "version_range_package_bytes": version_range_package_bytes,
        "version_range_system_bytes": version_range_system_bytes,
        "demotion_control": demotion_control,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_ID_FIELD_NAMES = ("chiplet_id", "package_id", "system_id")
_LIFECYCLE_FIELD_NAMES = (
    "lifecycle_chiplet_states", "lifecycle_package_states", "lifecycle_system_states",
)
_VERSION_RANGE_FIELD_NAMES = (
    "version_range_chiplet", "version_range_package", "version_range_system",
)


def _detect_ergonomic_keys(uc: Dict[str, Any]) -> list[str]:
    """Return the subset of `uc` keys whose values use an ergonomic shape.

    ID fields are ergonomic when shaped as a dict (sparse mapping or dense
    form); legacy hex / bytes / 32-int-list shapes remain raw-compatible to
    preserve byte-for-byte parity with legacy configs that combined
    `selector_bits` with a hex-string identity field.

    Lifecycle and `demotion_control` are ergonomic when shaped as a list;
    raw integer values stay raw-compatible. Version-range fields have no raw
    form, so any non-None value counts as ergonomic.
    """
    found = []
    for key in _ID_FIELD_NAMES:
        if isinstance(uc.get(key), dict):
            found.append(key)
    for key in _LIFECYCLE_FIELD_NAMES:
        if isinstance(uc.get(key), list):
            found.append(key)
    for key in _VERSION_RANGE_FIELD_NAMES:
        if uc.get(key) is not None:
            found.append(key)
    if isinstance(uc.get("demotion_control"), list):
        found.append("demotion_control")
    return found


def _decode_identity_field(
    value: Any,
    *,
    field_name: str,
    bit_offset: int,
    raw_selector_bits: int,
) -> tuple[bytes, int]:
    """Decode one ID field into (32 bytes, selector mask).

    Accepted shapes:
      - None → bytes = 0xA5 × 32, mask = 0.
      - Ergonomic sparse mapping: {byte_index: byte_value, ...} where
        byte_index ∈ 0..31 and byte_value ∈ 0..255. Mask bit i is set for
        every present key i.
      - Ergonomic dense + selection:
          {"value": [32 ints | bytes | 64-char hex],
           "selected": [byte_index, ...]}  OR  {"value": ..., "mask": int}.
        For unselected positions, value[i] MUST be 0xA5; non-0xA5 at an
        unselected index is rejected with a single-line error.
      - Legacy raw shapes: hex string / bytes / list of 32 ints with the
        producer's `selector_bits` driving the 0xA5 overlay.

    Returns (bytes, mask_int). For legacy shapes mask_int is 0 — the
    selector_bits accumulator picks them up directly from `raw_selector_bits`.
    """
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if value is None:
        return bytes([oca_consts.MANIFEST_UNUSED_BYTE] * 32), 0

    # --- Ergonomic shapes (dict) ---------------------------------------
    if isinstance(value, dict):
        if _is_sparse_mapping(value):
            raw, local_mask = _decode_identity_sparse(value, field_name=field_name)
        elif "value" in value:
            raw, local_mask = _decode_identity_dense(value, field_name=field_name)
        else:
            raise OcaConfigError(
                f"{field_name} dict must be either a sparse mapping "
                f"{{byte_index: byte_value, ...}} or a dense form "
                f"{{value: ..., selected/mask: ...}}",
                field_name=field_name,
            )
        return raw, local_mask << bit_offset

    # --- Legacy shapes (original raw mode) -----------------------------
    raw = _normalize_legacy_identity_bytes(value, field_name=field_name)
    out = bytearray(raw)
    for i in range(32):
        if not (raw_selector_bits >> (bit_offset + i)) & 1:
            out[i] = oca_consts.MANIFEST_UNUSED_BYTE
    return bytes(out), 0


def _is_sparse_mapping(value: dict) -> bool:
    """A sparse-mapping IdentitySpec is a dict whose keys are all ints."""
    return bool(value) and all(isinstance(k, int) for k in value.keys())


def _decode_identity_sparse(value: dict, *, field_name: str) -> tuple[bytes, int]:
    from .validators import OcaConfigError  # deferred to avoid import cycle

    out = bytearray([oca_consts.MANIFEST_UNUSED_BYTE] * 32)
    mask = 0
    for idx, byte_value in value.items():
        if not (0 <= idx < 32):
            raise OcaConfigError(
                f"{field_name} byte index {idx} out of range 0..31",
                field_name=field_name,
            )
        if not (isinstance(byte_value, int) and 0 <= byte_value <= 0xFF):
            raise OcaConfigError(
                f"{field_name} byte index {idx} value {byte_value!r} "
                f"out of range 0..255",
                field_name=field_name,
            )
        out[idx] = byte_value
        mask |= 1 << idx
    return bytes(out), mask


def _decode_identity_dense(value: dict, *, field_name: str) -> tuple[bytes, int]:
    from .validators import OcaConfigError  # deferred to avoid import cycle

    raw = _normalize_legacy_identity_bytes(value["value"], field_name=field_name)

    if "selected" in value and "mask" in value:
        raise OcaConfigError(
            f"{field_name} dense form accepts either `selected` or `mask`, "
            f"not both",
            field_name=field_name,
        )
    if "selected" in value:
        mask = _mask_from_selected_list(value["selected"], field_name=field_name)
    elif "mask" in value:
        mask = _mask_from_int(value["mask"], field_name=field_name)
    else:
        raise OcaConfigError(
            f"{field_name} dense form requires `selected` or `mask`",
            field_name=field_name,
        )

    bad_indices = [i for i in range(32) if not (mask >> i) & 1 and raw[i] != oca_consts.MANIFEST_UNUSED_BYTE]
    if bad_indices:
        raise OcaConfigError(
            f"{field_name} non-0xA5 at unselected byte indices {bad_indices}",
            field_name=field_name,
        )
    return bytes(raw), mask


def _mask_from_selected_list(selected: Any, *, field_name: str) -> int:
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if not isinstance(selected, (list, tuple)):
        raise OcaConfigError(
            f"{field_name} `selected` must be a list of byte indices",
            field_name=field_name,
        )
    mask = 0
    for idx in selected:
        if not (isinstance(idx, int) and 0 <= idx < 32):
            raise OcaConfigError(
                f"{field_name} `selected` entry {idx!r} out of range 0..31",
                field_name=field_name,
            )
        mask |= 1 << idx
    return mask


def _mask_from_int(mask_value: Any, *, field_name: str) -> int:
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if not isinstance(mask_value, int) or isinstance(mask_value, bool):
        raise OcaConfigError(
            f"{field_name} `mask` must be a 32-bit integer",
            field_name=field_name,
        )
    if not (0 <= mask_value < (1 << 32)):
        raise OcaConfigError(
            f"{field_name} `mask` 0x{mask_value:X} must fit in 32 bits",
            field_name=field_name,
        )
    return mask_value


def _normalize_legacy_identity_bytes(value: Any, *, field_name: str) -> bytes:
    """Accept the legacy ID shapes (hex string / bytes / list of 32) and
    return a 32-byte buffer. Used both for raw mode and as the `value` payload
    of the ergonomic dense form."""
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if isinstance(value, (bytes, bytearray)):
        if len(value) != 32:
            raise OcaConfigError(
                f"{field_name} must be 32 bytes; got {len(value)}",
                field_name=field_name,
            )
        return bytes(value)
    if isinstance(value, str):
        try:
            raw = bytes.fromhex(value)
        except ValueError as e:
            raise OcaConfigError(
                f"{field_name} hex string is malformed: {e}",
                field_name=field_name,
            ) from None
        if len(raw) != 32:
            raise OcaConfigError(
                f"{field_name} must encode 32 bytes; got {len(raw)}",
                field_name=field_name,
            )
        return raw
    if isinstance(value, list):
        if len(value) != 32:
            raise OcaConfigError(
                f"{field_name} list must have 32 entries; got {len(value)}",
                field_name=field_name,
            )
        out = bytearray(32)
        for i, b in enumerate(value):
            if not (isinstance(b, int) and 0 <= b <= 0xFF):
                raise OcaConfigError(
                    f"{field_name} byte index {i} value {b!r} out of range 0..255",
                    field_name=field_name,
                )
            out[i] = b
        return bytes(out)
    raise OcaConfigError(
        f"{field_name} must be hex string, bytes, or list of 32 ints",
        field_name=field_name,
    )


def _decode_lifecycle_field(value: Any, *, field_name: str) -> tuple[int, bool]:
    """Decode one lifecycle-states field into (bitmap, specified).

    Accepts:
      - None / absent → (0, False).
      - List of named tokens (e.g. ["TEST_DEV", "PROD_END"]) → OR'd bit values.
      - Empty list → (0, False), equivalent to absence.
      - Raw integer → passed through after a reserved-bit check (bits 7..31).

    Raises `OcaConfigError` for unrecognized names, the legacy spelling
    `RMA_SoP` (OCA-classic uses `RMA_SIP`), and raw-int values that
    intersect bits 7..31.
    """
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if value is None:
        return 0, False

    if isinstance(value, list):
        bitmap = 0
        for token in value:
            if not isinstance(token, str):
                raise OcaConfigError(
                    f"{field_name} list entry {token!r} is not a string",
                    field_name=field_name,
                )
            if token == "RMA_SoP":
                raise OcaConfigError(
                    f"{field_name} entry 'RMA_SoP' is a legacy spelling; "
                    f"OCA-classic uses 'RMA_SIP'",
                    field_name=field_name,
                )
            if token not in oca_consts.LIFECYCLE_STATE_NAMES:
                supported = ", ".join(sorted(oca_consts.LIFECYCLE_STATE_NAMES.keys()))
                raise OcaConfigError(
                    f"{field_name} entry {token!r} is not a known lifecycle "
                    f"state; supported: {supported}",
                    field_name=field_name,
                )
            bitmap |= 1 << oca_consts.LIFECYCLE_STATE_NAMES[token]
        return bitmap, bool(bitmap)

    if isinstance(value, int) and not isinstance(value, bool):
        if not (0 <= value < (1 << 32)):
            raise OcaConfigError(
                f"{field_name} raw integer 0x{value:X} must fit in 32 bits",
                field_name=field_name,
            )
        if value & oca_consts.LIFECYCLE_STATES_RESERVED_MASK:
            raise OcaConfigError(
                f"{field_name} raw integer 0x{value:X} has reserved bits "
                f"7..31 set",
                field_name=field_name,
            )
        return value, bool(value)

    raise OcaConfigError(
        f"{field_name} must be a list of named tokens or a 32-bit integer",
        field_name=field_name,
    )


def _decode_demotion_control(value: Any, *, field_name: str) -> int:
    """Decode the demotion_control field into a 16-bit integer.

    Accepts:
      - None / absent → 0.
      - List of named vendor flags (`BL1_DEMOTION_VALID`,
        `BL1_DEMOTION_ENABLE`, `BL2_DEMOTION_VALID`, `BL2_DEMOTION_ENABLE`).
        Bit positions are taken from `DEMOTION_CONTROL_FLAG_NAMES` and OR'd.
      - Raw integer (0..65535) with reserved bits 4..15 required to be zero.

    Raises `OcaConfigError` for unknown names, duplicate flags, raw integers
    that don't fit in 16 bits, and raw integers that intersect the reserved
    mask.
    """
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if value is None:
        return 0

    if isinstance(value, list):
        bitmap = 0
        seen = set()
        for token in value:
            if not isinstance(token, str):
                raise OcaConfigError(
                    f"{field_name} list entry {token!r} is not a string",
                    field_name=field_name,
                )
            if token not in oca_consts.DEMOTION_CONTROL_FLAG_NAMES:
                supported = ", ".join(sorted(oca_consts.DEMOTION_CONTROL_FLAG_NAMES.keys()))
                raise OcaConfigError(
                    f"{field_name} entry {token!r} is not a known demotion "
                    f"flag; supported: {supported}",
                    field_name=field_name,
                )
            if token in seen:
                raise OcaConfigError(
                    f"{field_name} contains duplicate flag {token!r}",
                    field_name=field_name,
                )
            seen.add(token)
            bitmap |= 1 << oca_consts.DEMOTION_CONTROL_FLAG_NAMES[token]
        return bitmap

    if isinstance(value, int) and not isinstance(value, bool):
        if not (0 <= value < (1 << 16)):
            raise OcaConfigError(
                f"{field_name} raw integer 0x{value:X} must fit in 16 bits",
                field_name=field_name,
            )
        if value & oca_consts.DEMOTION_CONTROL_RESERVED_MASK:
            raise OcaConfigError(
                f"{field_name} raw integer 0x{value:X} has reserved bits "
                f"4..15 set",
                field_name=field_name,
            )
        return value

    raise OcaConfigError(
        f"{field_name} must be a list of named flags or a 16-bit integer",
        field_name=field_name,
    )


_VERSION_RANGE_MIN_KEYS = ("major_min", "minor_min")
_VERSION_RANGE_MAX_KEYS = ("major_max", "minor_max")
_VERSION_RANGE_ALL_KEYS = _VERSION_RANGE_MIN_KEYS + _VERSION_RANGE_MAX_KEYS


def _decode_version_range_field(
    value: Any, *, field_name: str,
) -> tuple[bytes, bool, bool]:
    """Decode one version-range level into (8 bytes, min_specified, max_specified).

    The min half is "specified" iff `major_min` or `minor_min` is present in
    the input dict; same for the max half. Unspecified halves contribute four
    zero bytes. Missing keys inside a specified half default to 0.

    Byte layout (LE u16 words):
        bytes[0:2] minor_min
        bytes[2:4] major_min
        bytes[4:6] minor_max
        bytes[6:8] major_max

    Validates each key fits in 16 bits, rejects unknown keys, and rejects
    inverted ranges (when both halves are specified, the min tuple must be ≤
    the max tuple lexicographically by (major, minor)).
    """
    from .validators import OcaConfigError  # deferred to avoid import cycle

    if value is None:
        return b"\x00" * 8, False, False
    if not isinstance(value, dict):
        raise OcaConfigError(
            f"{field_name} must be a mapping with keys among "
            f"{_VERSION_RANGE_ALL_KEYS}",
            field_name=field_name,
        )

    unknown = [k for k in value.keys() if k not in _VERSION_RANGE_ALL_KEYS]
    if unknown:
        raise OcaConfigError(
            f"{field_name} has unknown keys {unknown}; supported keys: "
            f"{list(_VERSION_RANGE_ALL_KEYS)}",
            field_name=field_name,
        )

    min_specified = any(k in value for k in _VERSION_RANGE_MIN_KEYS)
    max_specified = any(k in value for k in _VERSION_RANGE_MAX_KEYS)

    parts = {}
    for key in _VERSION_RANGE_ALL_KEYS:
        v = int(value.get(key, 0))
        if not (0 <= v < (1 << 16)):
            raise OcaConfigError(
                f"{field_name}.{key} = {v} must fit in 16 bits (0..65535)",
                field_name=field_name,
            )
        parts[key] = v

    if min_specified and max_specified:
        min_tuple = (parts["major_min"], parts["minor_min"])
        max_tuple = (parts["major_max"], parts["minor_max"])
        if min_tuple > max_tuple:
            raise OcaConfigError(
                f"{field_name} inverted: "
                f"(major_min={parts['major_min']}, minor_min={parts['minor_min']}) "
                f"> (major_max={parts['major_max']}, minor_max={parts['minor_max']})",
                field_name=field_name,
            )

    packed = (
        struct.pack("<H", parts["minor_min"] if min_specified else 0)
        + struct.pack("<H", parts["major_min"] if min_specified else 0)
        + struct.pack("<H", parts["minor_max"] if max_specified else 0)
        + struct.pack("<H", parts["major_max"] if max_specified else 0)
    )
    return packed, min_specified, max_specified

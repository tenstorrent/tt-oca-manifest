# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Assemble several OCA manifest+payload bundles into one deployable image.

This builds a single flat binary that places one or more manifest+payload
"combos" (software banks) — plus optional opaque auxiliary data regions — at
caller-chosen byte offsets, with gaps filled by a configurable pad byte.

Assembly is independent of manifest+payload generation: each combo is produced
by the ordinary OCA bundle generator and is left byte-for-byte unchanged except
for its *unsigned* ``payload_offset`` field, which is reconciled to point at the
payload's placed location. Signed manifest bytes are never modified, and no
signing happens here — each referenced configuration owns its own signing.

The configuration is the authoritative map of the image; no header, index, or
other layout metadata is embedded in the output.
"""

from __future__ import annotations

import logging
import os
import struct
from collections import namedtuple
from typing import List, NoReturn, Optional, Tuple

from . import constants as oca_consts
from . import entry
from .validators import OcaConfigError
from ..utils import convert_to_int, load_config

logger = logging.getLogger(__name__)

DEFAULT_PAD_BYTE = 0xFF

KIND_MANIFEST = "manifest"
KIND_PAYLOAD = "payload"
KIND_AUXILIARY = "auxiliary"

# Internal placed region: a byte range occupied by one manifest body, one
# payload, or one auxiliary blob once positioned in the image.
_Region = namedtuple("_Region", ["name", "kind", "offset", "data"])


def _end(region: _Region) -> int:
    return region.offset + len(region.data)


def _fail(field_name: str, reason: str) -> NoReturn:
    """Raise a single-line, field-attributed configuration error."""
    raise OcaConfigError(reason, field_name=field_name, reason=reason)


def _require_field(mapping, key: str, prefix: str):
    if key not in mapping:
        _fail(f"{prefix}.{key}", "missing required field")
    return mapping[key]


def _coerce_int(value, field_name: str) -> int:
    try:
        return convert_to_int(value)
    except (ValueError, TypeError):
        _fail(field_name, f"expected an integer, got {value!r}")


def _register_name(seen: dict, name: str, field_name: str) -> None:
    if name in seen:
        _fail(field_name, f"duplicate name {name!r} (names must be unique across all entries)")
    seen[name] = field_name


def _payload_image_layout(payload: bytes) -> List[Tuple[int, int]]:
    """Return per-image ``(payload_relative_offset, length)`` parsed from the TOC."""
    if payload[0:4] != oca_consts.PTOC_MAGIC:
        _fail("payload", "generated payload does not begin with the expected TOC magic")
    image_count = struct.unpack_from("<Q", payload, oca_consts.OFF_TOC_IMAGE_COUNT)[0]
    layout = []
    for i in range(image_count):
        base = oca_consts.TOC_HEADER_SIZE + i * oca_consts.TOC_ENTRY_SIZE
        rel_offset = struct.unpack_from(
            "<Q", payload, base + oca_consts.OFF_TOC_ENTRY_OFFSET)[0]
        length = struct.unpack_from(
            "<Q", payload, base + oca_consts.OFF_TOC_ENTRY_LENGTH)[0]
        layout.append((rel_offset, length))
    return layout


def _resolve_list_payload_base(payload: bytes, offsets_raw, prefix: str) -> int:
    """Validate a per-image offset list and derive the single payload base.

    Each listed offset positions one payload image. Because the payload (TOC +
    images) is contiguous and the per-image offsets live in the signed TOC, the
    list must be consistent with that layout — i.e. all images must imply the
    same payload base. Inconsistent or wrongly-sized lists are rejected.
    """
    layout = _payload_image_layout(payload)
    if len(offsets_raw) != len(layout):
        _fail(
            f"{prefix}.payload_offset",
            f"list has {len(offsets_raw)} offsets but the payload has {len(layout)} image(s)",
        )
    bases = set()
    for i, (rel_offset, _length) in enumerate(layout):
        off = _coerce_int(offsets_raw[i], f"{prefix}.payload_offset[{i}]")
        if off < 0:
            _fail(f"{prefix}.payload_offset[{i}]", f"must be non-negative; got {off}")
        if off % oca_consts.PAYLOAD_IMAGE_ALIGNMENT != 0:
            _fail(
                f"{prefix}.payload_offset[{i}]",
                f"must be {oca_consts.PAYLOAD_IMAGE_ALIGNMENT}-byte aligned; got {off:#x}",
            )
        bases.add(off - rel_offset)
    if len(bases) != 1:
        _fail(
            f"{prefix}.payload_offset",
            "per-image offsets are inconsistent with the payload layout "
            "(cannot derive a single payload base)",
        )
    payload_base = bases.pop()
    if payload_base < 0:
        _fail(f"{prefix}.payload_offset", "derived payload base is negative")
    return payload_base


def _build_combo_regions(combo, index: int) -> Tuple[str, List[_Region]]:
    prefix = f"combos[{index}]"
    name = _require_field(combo, "name", prefix)
    cfg_path = _require_field(combo, "config", prefix)
    manifest_offset = _coerce_int(_require_field(combo, "manifest_offset", prefix),
                                  f"{prefix}.manifest_offset")
    if "payload_offset" not in combo:
        _fail(f"{prefix}.payload_offset", "missing required field")
    payload_offset_raw = combo["payload_offset"]

    if manifest_offset < 0:
        _fail(f"{prefix}.manifest_offset", f"must be non-negative; got {manifest_offset}")

    ref_config = load_config(cfg_path)
    if ref_config is None:
        _fail(f"{prefix}.config", f"cannot read OCA configuration {str(cfg_path)!r}")
    ref_format = ref_config.get("manifest_format")
    if ref_format == "oca-classic":
        ref_variant = oca_consts.CLASSIC_VARIANT
    elif ref_format == "oca-pqc":
        ref_variant = oca_consts.PQC_VARIANT
    else:
        _fail(
            f"{prefix}.config",
            f"referenced configuration must be oca-classic or oca-pqc, got {ref_format!r}",
        )

    # Reuse the ordinary generator unchanged; attribute any failure to this combo.
    try:
        bundle = entry.pack_oca_bundle(ref_config)
    except OcaConfigError as exc:
        raise OcaConfigError(
            exc.reason,
            field_name=f"{prefix}.config ({exc.field_name})",
            reason=exc.reason,
            deferred_feature=exc.deferred_feature,
        )

    manifest_body = bytearray(bundle[: ref_variant.body_size])
    payload = bundle[ref_variant.body_size:]

    if isinstance(payload_offset_raw, list):
        payload_base = _resolve_list_payload_base(payload, payload_offset_raw, prefix)
    else:
        payload_base = _coerce_int(payload_offset_raw, f"{prefix}.payload_offset")
        if payload_base < 0:
            _fail(f"{prefix}.payload_offset", f"must be non-negative; got {payload_base}")
        if payload_base % oca_consts.PAYLOAD_IMAGE_ALIGNMENT != 0:
            _fail(
                f"{prefix}.payload_offset",
                f"must be {oca_consts.PAYLOAD_IMAGE_ALIGNMENT}-byte aligned; got {payload_base:#x}",
            )

    # Reconcile the unsigned payload_offset (relative to the manifest body) to the
    # placed location. The payload_offset field sits outside each variant's signed
    # region, so the signature and every signed/hashed byte are untouched.
    struct.pack_into("<q", manifest_body, ref_variant.payload_offset_field, payload_base - manifest_offset)

    regions = [
        _Region(f"{name}.manifest", KIND_MANIFEST, manifest_offset, bytes(manifest_body)),
        _Region(f"{name}.payload", KIND_PAYLOAD, payload_base, payload),
    ]
    return name, regions


def _build_aux_region(aux, index: int) -> Tuple[str, _Region]:
    prefix = f"auxiliary_regions[{index}]"
    name = _require_field(aux, "name", prefix)
    path = _require_field(aux, "path", prefix)
    offset = _coerce_int(_require_field(aux, "offset", prefix), f"{prefix}.offset")
    if offset < 0:
        _fail(f"{prefix}.offset", f"must be non-negative; got {offset}")
    try:
        with open(str(path), "rb") as fh:
            data = fh.read()
    except OSError as exc:
        _fail(f"{prefix}.path", f"cannot read auxiliary file {str(path)!r}: {exc.strerror or exc}")
    return name, _Region(name, KIND_AUXILIARY, offset, data)


def _check_overlaps(regions: List[_Region]) -> None:
    for i in range(len(regions)):
        a = regions[i]
        for j in range(i + 1, len(regions)):
            b = regions[j]
            if a.offset < _end(b) and b.offset < _end(a):
                _fail(
                    "layout",
                    f"region {a.name!r} [{a.offset:#x}, {_end(a):#x}) overlaps "
                    f"region {b.name!r} [{b.offset:#x}, {_end(b):#x})",
                )


def _assemble(regions: List[_Region], pad_byte: int, total_size: Optional[int]) -> bytes:
    max_end = max((_end(r) for r in regions), default=0)
    size = total_size if total_size is not None else max_end
    image = bytearray(bytes([pad_byte]) * size)
    for r in regions:
        image[r.offset : _end(r)] = r.data
    return bytes(image)


def pack_combined_image(config_data, output_path: Optional[str] = None,
                        verbose: bool = False) -> bytes:
    """Assemble the combined deployable image described by ``config_data``.

    Returns the flat image bytes. If ``output_path`` is given, also writes them.
    Validates the entire layout before producing any output, so a rejected
    configuration writes nothing.
    """
    combos = config_data.get("combos")
    if not combos or not isinstance(combos, list):
        _fail("combos", "at least one combo is required")

    pad_byte = _coerce_int(config_data.get("pad_byte", DEFAULT_PAD_BYTE), "pad_byte")
    if not (0 <= pad_byte <= 255):
        _fail("pad_byte", f"must be in 0..255; got {pad_byte}")

    total_size = config_data.get("total_size")
    if total_size is not None:
        total_size = _coerce_int(total_size, "total_size")
        if total_size <= 0:
            _fail("total_size", f"must be positive; got {total_size}")

    image_name = config_data.get("name")

    # Pass 1: build every region and validate the full layout (no output yet).
    seen_names: dict = {}
    regions: List[_Region] = []
    for i, combo in enumerate(combos):
        name, combo_regions = _build_combo_regions(combo, i)
        _register_name(seen_names, name, f"combos[{i}].name")
        regions.extend(combo_regions)

    for i, aux in enumerate(config_data.get("auxiliary_regions") or []):
        name, region = _build_aux_region(aux, i)
        _register_name(seen_names, name, f"auxiliary_regions[{i}].name")
        regions.append(region)

    if total_size is not None:
        for r in regions:
            if _end(r) > total_size:
                _fail(
                    "total_size",
                    f"region {r.name!r} ends at {_end(r):#x}, beyond total_size {total_size:#x}",
                )

    _check_overlaps(regions)

    # Pass 2: materialize the image.
    image = _assemble(regions, pad_byte, total_size)

    if image_name:
        logger.info("oca-combined: image %r", str(image_name))
    for r in sorted(regions, key=lambda r: r.offset):
        logger.info("oca-combined: region %-24s off=%#010x len=%#x", r.name, r.offset, len(r.data))
    logger.info(
        "oca-combined: %d-byte image (%d combo(s), %d region(s))",
        len(image), len(combos), len(regions),
    )

    if output_path is not None:
        out_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "wb") as fh:
            fh.write(image)
        logger.info("oca-combined: wrote %d bytes to %s", len(image), output_path)

    return image

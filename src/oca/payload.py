"""OCA payload assembly: TOC + image bytes + payload-level hash computation.

Public functions:
  * assemble_multi_image_payload(images) — full multi-image assembly with
    offset auto-assignment, 8-byte alignment validation, overlap detection,
    and a uint64 bound on the total payload length.
  * compute_payload_hashes(...)          — payload_hash + payload_hash_chain.

`build_single_image_payload` is a thin wrapper around
`assemble_multi_image_payload` that always calls it with a 1-element list, so
the single-image and multi-image code paths share the same validation,
hashing, and byte-layout logic.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Tuple

from . import constants as oca_consts
from .toc import build_toc_entry, build_toc_header
from .validators import OcaConfigError, OcaLayoutError


UINT64_MAX = (1 << 64) - 1

# Per-image TOC-entry fields that are optional in the YAML config. They are
# carried verbatim from config to `build_toc_entry`, which supplies the default
# and enforces the range/encoding rules for each.
OPTIONAL_ENTRY_FIELDS = (
    "security_version",
    "load_addr",
    "entry_point",
    "target_chiplet_id",
    "description",
)


def _next_aligned(pos: int) -> int:
    """Round `pos` up to the next multiple of PAYLOAD_IMAGE_ALIGNMENT (8)."""
    mis = pos % oca_consts.PAYLOAD_IMAGE_ALIGNMENT
    return pos if mis == 0 else pos + (oca_consts.PAYLOAD_IMAGE_ALIGNMENT - mis)


def assemble_multi_image_payload(
    images: List[Dict[str, Any]],
) -> Tuple[bytes, int, List[Tuple[int, int]]]:
    """Assemble a multi-image OCA payload.

    Returns (payload_bytes, toc_byte_count, entry_image_byte_ranges).

    Steps:
      1. Reject empty image lists (caught earlier by the validator too;
         second line of defense here).
      2. Read each image's bytes from disk; record (label, length).
      3. Validate or auto-assign each image's payload-relative `offset`:
           - explicit offsets MUST be multiples of 8 and not overlap any sibling
           - absent/None offsets are auto-assigned to the next available
             8-byte-aligned slot after all explicit and prior auto entries
      4. Verify no overlap across the final offset/length set.
      5. Compute total payload length and assert it fits in unsigned 64 bits.
      6. Build the TOC header + entries (in ascending-offset order) and
         concatenate with the image bytes + per-image alignment padding.
    """
    if not images:
        raise OcaConfigError(
            "payload_images must contain at least one image for oca-classic",
            field_name="payload_images",
        )

    # --- 1. Load each image's bytes + record per-image metadata. ---
    loaded: List[Dict[str, Any]] = []
    for idx, image in enumerate(images):
        path = image.get("path")
        if not path:
            raise OcaConfigError(
                f"payload_images[{idx}]: missing required field 'path'",
                field_name="payload_images",
            )
        with open(path, "rb") as fh:
            data = fh.read()
        explicit_offset = image.get("offset")
        if explicit_offset is not None:
            explicit_offset = int(explicit_offset)
            if explicit_offset < 0:
                raise OcaConfigError(
                    f"payload_images[{idx}] (path={path}): offset must be ≥ 0; got {explicit_offset}",
                    field_name="payload_images",
                )
            if explicit_offset % oca_consts.PAYLOAD_IMAGE_ALIGNMENT != 0:
                raise OcaConfigError(
                    f"payload_images[{idx}] (path={path}): offset {hex(explicit_offset)} "
                    f"is not aligned to {oca_consts.PAYLOAD_IMAGE_ALIGNMENT} bytes",
                    field_name="payload_images",
                )
        loaded.append(
            {
                "idx": idx,
                "path": path,
                "type": image.get("type", "_VENDOR1 BLSTAGE1"),
                "group": int(image.get("group", 0)),
                "version": image.get("version") or {},
                "bytes": data,
                "length": len(data),
                "explicit_offset": explicit_offset,
                # Optional TOC-entry fields; build_toc_entry defaults each to 0 /
                # an all-zero field and range-checks whatever is supplied.
                **{key: image.get(key) for key in OPTIONAL_ENTRY_FIELDS},
            }
        )

    # --- 2. Assign offsets: explicit values keep their slot; absent values
    #         flow into the next aligned position after all explicit entries
    #         and prior auto entries. ---
    image_count = len(loaded)
    toc_byte_count = oca_consts.TOC_HEADER_SIZE + image_count * oca_consts.TOC_ENTRY_SIZE

    explicit = [im for im in loaded if im["explicit_offset"] is not None]
    explicit.sort(key=lambda im: im["explicit_offset"])

    # Check explicit-set overlap and TOC overlap before assigning auto offsets.
    for im in explicit:
        if im["explicit_offset"] < toc_byte_count:
            raise OcaConfigError(
                f"payload_images[{im['idx']}] (path={im['path']}): offset "
                f"{hex(im['explicit_offset'])} would overlap the TOC region "
                f"[0, {toc_byte_count})",
                field_name="payload_images",
            )
    for a, b in zip(explicit, explicit[1:]):
        a_end = a["explicit_offset"] + a["length"]
        if a_end > b["explicit_offset"]:
            raise OcaConfigError(
                f"payload_images[{a['idx']}] (offset={hex(a['explicit_offset'])}, length={a['length']}) "
                f"overlaps payload_images[{b['idx']}] (offset={hex(b['explicit_offset'])}, length={b['length']})",
                field_name="payload_images",
            )

    # Compute auto-assigned offsets: place absent entries one by one starting at
    # the next aligned position after the running cursor, hopping over any
    # explicit-offset image regions.
    sorted_explicit_ranges = [
        (im["explicit_offset"], im["explicit_offset"] + im["length"]) for im in explicit
    ]

    cursor = _next_aligned(toc_byte_count)
    for im in loaded:
        if im["explicit_offset"] is not None:
            continue
        # Advance the cursor past any explicit ranges that begin at or before it.
        moved = True
        while moved:
            moved = False
            for lo, hi in sorted_explicit_ranges:
                if cursor < hi and cursor + im["length"] > lo:
                    cursor = _next_aligned(hi)
                    moved = True
                    break
        im["offset"] = cursor
        cursor = _next_aligned(cursor + im["length"])

    # Fill in offset for the explicit entries (they already have it).
    for im in explicit:
        im["offset"] = im["explicit_offset"]

    # --- 3. Final overlap check across the full set (defense-in-depth). ---
    loaded_sorted = sorted(loaded, key=lambda im: im["offset"])
    for a, b in zip(loaded_sorted, loaded_sorted[1:]):
        a_end = a["offset"] + a["length"]
        if a_end > b["offset"]:
            raise OcaConfigError(
                f"payload_images[{a['idx']}] (offset={hex(a['offset'])}, length={a['length']}) "
                f"overlaps payload_images[{b['idx']}] (offset={hex(b['offset'])}, length={b['length']})",
                field_name="payload_images",
            )

    # --- 4. Compute payload length, bound-check against uint64. ---
    last = loaded_sorted[-1]
    payload_length = last["offset"] + last["length"]
    if payload_length > UINT64_MAX:
        raise OcaConfigError(
            f"computed payload_length {payload_length} exceeds the unsigned 64-bit "
            f"limit ({UINT64_MAX}); reduce image sizes or offsets",
            field_name="payload_images",
        )

    # --- 5. Build TOC header + entries in ascending-offset order. ---
    header = build_toc_header(payload_length=payload_length, image_count=image_count)
    entries_bytes = bytearray()
    entry_image_byte_ranges: List[Tuple[int, int]] = []
    for im in loaded_sorted:
        entry_meta = {
            "type": im["type"],
            "group": im["group"],
            "offset": im["offset"],
            "length": im["length"],
            "version": im["version"],
            **{key: im[key] for key in OPTIONAL_ENTRY_FIELDS},
        }
        entries_bytes += build_toc_entry(entry_meta, im["bytes"])
        entry_image_byte_ranges.append((im["offset"], im["length"]))

    # --- 6. Assemble: header + entries + image bytes (with per-image alignment padding). ---
    payload = bytearray()
    payload += header
    payload += entries_bytes
    cursor = len(payload)  # bytes written so far = TOC_HEADER + N*TOC_ENTRY
    for im in loaded_sorted:
        # Pad with 0x00 from cursor up to im["offset"] (inter-image gap or alignment).
        if im["offset"] < cursor:
            # Should be impossible given overlap-check above.
            raise AssertionError(
                f"internal: image at offset {im['offset']} starts before cursor {cursor}"
            )
        if im["offset"] > cursor:
            payload += b"\x00" * (im["offset"] - cursor)
            cursor = im["offset"]
        payload += im["bytes"]
        cursor += im["length"]

    # Final tail padding if payload_length extends past the last image.
    # Today payload_length is always set to `cursor` so this is a no-op; the
    # branch stays in place for future variants that reserve trailing space
    # for in-place updates.
    if cursor < payload_length:
        payload += b"\x00" * (payload_length - cursor)

    if len(payload) != payload_length:
        raise OcaLayoutError(
            f"assembled payload length {len(payload)} != computed "
            f"payload_length {payload_length}"
        )
    return bytes(payload), toc_byte_count, entry_image_byte_ranges


def build_single_image_payload(
    image: Dict[str, Any],
) -> Tuple[bytes, int, List[Tuple[int, int]]]:
    """Backward-compatible single-image wrapper.

    Now implemented as a 1-element call to assemble_multi_image_payload so
    the single- and multi-image paths share identical layout and validation
    semantics.
    """
    return assemble_multi_image_payload([image])


def compute_payload_hashes(
    payload_bytes: bytes,
    toc_byte_count: int,
    entry_image_byte_ranges: Iterable[Tuple[int, int]],
    ciphertext: bytes = None,
) -> Tuple[bytes, bytes]:
    """Compute the two payload-level hash fields:

      payload_hash       = digest of the stored payload the Consumer authenticates
                           first: the full `ciphertext` when the payload is
                           encrypted, otherwise the cleartext TOC bytes.
      payload_hash_chain = iterative digest chain over the *plaintext* TOC + every
                           image entry; anchors the recovered plaintext back to the
                           manifest. Computed identically on both paths.

    Returns (payload_hash_field, payload_hash_chain_field), each 64 bytes with
    the digest at offset 0 and trailing 0x00 bytes. This pass uses SHA-256
    (payload_hash_type = 0x01); the field width accommodates other digest types
    the format permits.
    """
    if ciphertext is not None:
        payload_hash_digest = hashlib.sha256(ciphertext).digest()
    else:
        payload_hash_digest = hashlib.sha256(payload_bytes[:toc_byte_count]).digest()
    payload_hash_field = payload_hash_digest.ljust(oca_consts.HASH_FIELD_SIZE, b"\x00")

    h = hashlib.sha256(payload_bytes[:toc_byte_count]).digest()
    for off, ln in entry_image_byte_ranges:
        entry_hash = hashlib.sha256(payload_bytes[off : off + ln]).digest()
        h = hashlib.sha256(h + entry_hash).digest()
    payload_hash_chain_field = h.ljust(oca_consts.HASH_FIELD_SIZE, b"\x00")

    return payload_hash_field, payload_hash_chain_field

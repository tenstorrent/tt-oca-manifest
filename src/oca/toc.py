"""OCA payload TOC header (32 bytes) and TOC entry (276 bytes) builders.

Source-of-truth byte layouts: contracts/oca-payload-toc.md, which mirrors the
"Payload TOC" / "Payload TOC entry" tables in the OCA spec. Every field is
written through an `OFF_TOC_*` constant so the packer and the C validator
address the same bytes.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict

from . import constants as oca_consts
from .validators import OcaConfigError


UINT64_MAX = (1 << 64) - 1

# Per-image config keys that map straight onto an unsigned 64-bit TOC entry
# field. All default to 0, which the spec defines as "unused" for each of them.
_U64_ENTRY_FIELDS = {
    "security_version": oca_consts.OFF_TOC_ENTRY_SECURITY_VERSION,
    "load_addr": oca_consts.OFF_TOC_ENTRY_LOAD_ADDR,
    "entry_point": oca_consts.OFF_TOC_ENTRY_ENTRY_POINT,
    "target_chiplet_id": oca_consts.OFF_TOC_ENTRY_TARGET_CHIPLET_ID,
}


def build_toc_header(payload_length: int, image_count: int) -> bytes:
    """Build the 32-byte PTOC header per contracts/oca-payload-toc.md."""
    if image_count < 1:
        raise ValueError(f"image_count must be ≥ 1; got {image_count}")
    if payload_length < 0:
        raise ValueError(f"payload_length must be ≥ 0; got {payload_length}")
    if payload_length >= (1 << 64):
        raise ValueError(
            f"payload_length must fit in an unsigned 64-bit integer "
            f"(< 2**64 = {1 << 64}); got {payload_length}"
        )

    header = bytearray(oca_consts.TOC_HEADER_SIZE)
    header[oca_consts.OFF_TOC_MAGIC:
           oca_consts.OFF_TOC_MAGIC + 4] = oca_consts.PTOC_MAGIC
    struct.pack_into("<H", header, oca_consts.OFF_TOC_VERSION_MAJOR,
                     oca_consts.TOC_VERSION_MAJOR)
    struct.pack_into("<H", header, oca_consts.OFF_TOC_VERSION_MINOR,
                     oca_consts.TOC_VERSION_MINOR)
    struct.pack_into("<Q", header, oca_consts.OFF_TOC_PAYLOAD_LENGTH, payload_length)
    struct.pack_into("<Q", header, oca_consts.OFF_TOC_IMAGE_COUNT, image_count)
    # 24..32 stays reserved / 0x00.
    return bytes(header)


def _u64_entry_value(image_meta: Dict[str, Any], key: str) -> int:
    """Read an optional unsigned-64-bit TOC entry field, defaulting to 0."""
    raw = image_meta.get(key)
    if raw is None:
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise OcaConfigError(
            f"image.{key} must be an integer; got {raw!r}",
            field_name="payload_images",
        ) from None
    if not (0 <= value <= UINT64_MAX):
        raise OcaConfigError(
            f"image.{key} must fit in an unsigned 64-bit integer "
            f"(0 ≤ value ≤ {UINT64_MAX}); got {value}",
            field_name="payload_images",
        )
    return value


def _description_field(image_meta: Dict[str, Any]) -> bytes:
    """Encode `image.description` into the 128-byte NUL-terminated field.

    The spec requires byte 127 to be 0x00, so at most 127 characters of text
    fit. An absent description yields an all-zero field.
    """
    text = image_meta.get("description")
    if text is None:
        return b"\x00" * oca_consts.LEN_TOC_ENTRY_DESCRIPTION
    if not isinstance(text, str):
        raise OcaConfigError(
            f"image.description must be a string; got {type(text).__name__}",
            field_name="payload_images",
        )
    if len(text) > oca_consts.TOC_ENTRY_DESCRIPTION_MAX_TEXT:
        raise OcaConfigError(
            f"image.description must be ≤ {oca_consts.TOC_ENTRY_DESCRIPTION_MAX_TEXT} "
            f"ASCII chars (byte 127 is the NUL terminator); got {len(text)}",
            field_name="payload_images",
        )
    try:
        encoded = text.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise OcaConfigError(
            "image.description must be ASCII",
            field_name="payload_images",
        ) from None
    return encoded.ljust(oca_consts.LEN_TOC_ENTRY_DESCRIPTION, b"\x00")


def build_toc_entry(image_meta: Dict[str, Any], image_bytes: bytes) -> bytes:
    """Build a 276-byte TOC entry for one image.

    image_meta:
        type              : ≤16-char ASCII string (right-padded with space to 16 B)
        group             : int (default 0)
        offset            : int (payload-relative byte offset)
        length            : int (must equal len(image_bytes))
        version           : dict {major, minor, patch} (default 0.0.0)
        security_version  : int (default 0 — "unused" per the spec)
        load_addr         : int (default 0)
        entry_point       : int (default 0)
        target_chiplet_id : int (default 0)
        description       : ≤127-char ASCII string (default all-zero field)

    Bytes not covered by a field above are the entry's two reserved regions
    (76..80 and 272..276), which the spec requires the Producer to zero.
    """
    image_type = image_meta.get("type", "_VENDOR1 BLSTAGE1")
    if not isinstance(image_type, str):
        raise OcaConfigError("image.type must be a string", field_name="payload_images")
    if len(image_type) > oca_consts.LEN_TOC_ENTRY_TYPE:
        raise OcaConfigError(
            f"image.type must be ≤ {oca_consts.LEN_TOC_ENTRY_TYPE} ASCII chars; "
            f"got {len(image_type)}",
            field_name="payload_images",
        )
    try:
        type_bytes = image_type.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        raise OcaConfigError("image.type must be ASCII", field_name="payload_images") from None
    type_bytes = type_bytes.ljust(oca_consts.LEN_TOC_ENTRY_TYPE, b" ")

    group = int(image_meta.get("group", 0))
    offset = int(image_meta["offset"])
    length = int(image_meta["length"])
    if length != len(image_bytes):
        raise ValueError(f"image.length {length} does not match image bytes {len(image_bytes)}")

    version = image_meta.get("version") or {}
    major = int(version.get("major", 0))
    minor = int(version.get("minor", 0))
    patch = int(version.get("patch", 0))
    if not (0 <= major < (1 << 16)):
        raise OcaConfigError("image.version.major must fit in 16 bits",
                             field_name="payload_images")
    if not (0 <= minor < (1 << 24)):
        raise OcaConfigError("image.version.minor must fit in 24 bits",
                             field_name="payload_images")
    if not (0 <= patch < (1 << 24)):
        raise OcaConfigError("image.version.patch must fit in 24 bits",
                             field_name="payload_images")
    packed_version = (major << 48) | (minor << 24) | patch

    image_hash = hashlib.sha256(image_bytes).digest()
    image_hash_field = image_hash.ljust(oca_consts.HASH_FIELD_SIZE, b"\x00")

    entry = bytearray(oca_consts.TOC_ENTRY_SIZE)
    entry[oca_consts.OFF_TOC_ENTRY_TYPE:
          oca_consts.OFF_TOC_ENTRY_TYPE + oca_consts.LEN_TOC_ENTRY_TYPE] = type_bytes
    struct.pack_into("<I", entry, oca_consts.OFF_TOC_ENTRY_GROUP, group)
    struct.pack_into("<Q", entry, oca_consts.OFF_TOC_ENTRY_OFFSET, offset)
    struct.pack_into("<Q", entry, oca_consts.OFF_TOC_ENTRY_LENGTH, length)
    struct.pack_into("<Q", entry, oca_consts.OFF_TOC_ENTRY_VERSION, packed_version)
    for key, field_offset in _U64_ENTRY_FIELDS.items():
        struct.pack_into("<Q", entry, field_offset, _u64_entry_value(image_meta, key))
    entry[oca_consts.OFF_TOC_ENTRY_HASH:
          oca_consts.OFF_TOC_ENTRY_HASH + oca_consts.HASH_FIELD_SIZE] = image_hash_field
    entry[oca_consts.OFF_TOC_ENTRY_DESCRIPTION:
          oca_consts.OFF_TOC_ENTRY_DESCRIPTION + oca_consts.LEN_TOC_ENTRY_DESCRIPTION] = \
        _description_field(image_meta)
    return bytes(entry)

# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA configuration validation and normalization (oca-classic and oca-pqc).

Public functions:
  * OcaConfigError — exception with field_name / deferred_feature attributes.
  * validate_and_normalize_oca_classic(config) — validate required fields,
    delegate the usage_constraints block to the dedicated decoder, normalize
    description NUL-padding, manifest_identifier ASCII-padding, and zero
    secure-boot-only fields when secure_boot is disabled.
  * reject_deferred_features(config) — flag unsupported config keys with a
    single-line error before any byte-layout work.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from . import constants as oca_consts


class OcaLayoutError(AssertionError):
    """A manifest byte-layout invariant failed while assembling a bundle.

    Distinct from `OcaConfigError`: that one means the *configuration* is wrong
    and is the producer's to fix, whereas this means the *packer* mis-assembled
    the bytes — a bug in this code, not in the input. Every value reaching the
    builders has already been validated.

    A `raise` rather than the bare `assert` it replaced, because `python -O`
    strips asserts: a layout slip would then go unreported and emit a malformed
    *signed* manifest. Subclasses AssertionError to preserve what the previous
    bare asserts raised.
    """


class OcaConfigError(ValueError):
    """Raised when an OCA-classic configuration fails validation."""

    def __init__(
        self,
        message: str,
        *,
        field_name: str,
        deferred_feature: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.field_name = field_name
        self.deferred_feature = deferred_feature
        self.reason = reason if reason is not None else message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require(config: Dict[str, Any], key: str, context: str = "oca-classic") -> Any:
    if key not in config:
        raise OcaConfigError(
            f"missing required field for {context}: {key}",
            field_name=key,
        )
    return config[key]


# The fields that describe each signature class's key and signature. A class the
# manifest does not enforce has no signature, so naming one of these for it is a
# configuration mistake, not something to zero silently. The revocation bitmaps
# are not among them: a verified manifest commits every bitmap it carries,
# whichever class signed it.
CLASSIC_SIGNING_FIELDS = (
    "signature_type", "signing_authority", "signing_key_file", "signing_key_id",
    "public_key_select_classic", "signature_encoding", "public_key_encoding",
)
PQC_SIGNING_FIELDS = (
    "signature_type_pqc", "signing_authority_pqc", "signing_key_file_pqc",
    "signing_key_id_pqc", "public_key_select_pqc", "signature_encoding_pqc",
    "public_key_encoding_pqc",
)


def _class_bit(config: Dict[str, Any], field: str, default: int) -> int:
    value = int(config.get(field, default))
    if value not in (0, 1):
        raise OcaConfigError(f"{field} must be 0 or 1; got {value}", field_name=field)
    return value


def _normalize_signature_classes(config: Dict[str, Any], secure_boot: int,
                                 manifest_format: str) -> tuple:
    """Resolve secure_boot_classic and secure_boot_pqc, the signature classes
    secure_boot_control names.

    The classical class defaults on under secure boot, so a config that names
    neither class enforces the classical one. A PQC manifest
    may enforce either class or both, a classic manifest the classical class
    only, and secure boot must name at least one.
    """
    classic = _class_bit(config, "secure_boot_classic", 1 if secure_boot == 1 else 0)
    pqc = _class_bit(config, "secure_boot_pqc", 0)
    if pqc and manifest_format != "oca-pqc":
        raise OcaConfigError(
            "secure_boot_pqc names a PQC signature, which only an oca-pqc manifest "
            "can carry",
            field_name="secure_boot_pqc",
        )
    if secure_boot == 0:
        for field, value in (("secure_boot_classic", classic), ("secure_boot_pqc", pqc)):
            if value:
                raise OcaConfigError(f"{field} requires secure_boot: 1", field_name=field)
    elif not (classic or pqc):
        raise OcaConfigError(
            "secure_boot: 1 needs at least one signature class: set "
            "secure_boot_classic or secure_boot_pqc",
            field_name="secure_boot",
        )
    return classic, pqc


def _reject_fields_for_disabled_class(config: Dict[str, Any], fields: tuple,
                                      requirement: str) -> None:
    """Refuse a signing field named for a signature class that is not enforced."""
    for field in fields:
        if _truthy(config, field):
            raise OcaConfigError(
                f"{field} describes a signature this manifest does not carry; it "
                f"requires {requirement}",
                field_name=field,
            )


def _reject_integrator_encoding(field: str, value: int) -> None:
    if value in oca_consts.INTEGRATOR_ENCODINGS:
        raise OcaConfigError(
            f"OCA feature deferred to future pass: integrator-defined encoding "
            f"(field {field})",
            field_name=field,
            deferred_feature="integrator-defined encoding",
        )


def _classic_encoding(config: Dict[str, Any], field: str) -> int:
    value = int(config.get(field, oca_consts.OcaClassicSignatureEncoding.RAW_BYTES.value))
    if value in oca_consts.OCA_SELECTABLE_ENCODINGS:
        return value
    _reject_integrator_encoding(field, value)
    raise OcaConfigError(
        f"{field} must be one of {oca_consts.OCA_SELECTABLE_ENCODINGS_TEXT}; got {value:#x}",
        field_name=field,
    )


def _pqc_encoding(config: Dict[str, Any], field: str) -> int:
    value = int(config.get(field, oca_consts.OcaClassicSignatureEncoding.RAW_BYTES.value))
    if value in oca_consts.PQC_SELECTABLE_ENCODINGS:
        return value
    if value == oca_consts.OcaClassicSignatureEncoding.ASN1_DER.value:
        raise OcaConfigError(
            f"{field} 0x01 (DER) is reserved for PQC: FIPS 204 defines no bare ASN.1 "
            f"structure for an ML-DSA key or signature. Use 0x02 (raw bytes).",
            field_name=field,
        )
    _reject_integrator_encoding(field, value)
    raise OcaConfigError(f"{field} must be 0x02 (raw bytes); got {value:#x}", field_name=field)


def _normalize_pqc_signing(config: Dict[str, Any], out: Dict[str, Any],
                           secure_boot: int, pqc: int, manifest_format: str) -> None:
    """Validate the PQC class's signing description and revocation bitmap into
    `out`."""
    for field in ("public_key_pqc", "signature_pqc"):
        if _truthy(config, field):
            raise OcaConfigError(
                f"{field} is produced by the packer from the signing key; it is not a "
                f"config input",
                field_name=field,
            )

    if not pqc:
        _reject_fields_for_disabled_class(
            config, PQC_SIGNING_FIELDS, "secure_boot: 1 and secure_boot_pqc: 1")
        out["signature_type_pqc"] = 0
        out["public_key_select_pqc"] = 0
        out["signature_encoding_pqc"] = 0
        out["public_key_encoding_pqc"] = 0
    else:
        context = "the PQC signature class"
        sig_type = int(_require(config, "signature_type_pqc", context))
        if sig_type != oca_consts.OcaPqcSignatureType.ML_DSA_87.value:
            raise OcaConfigError(
                f"signature_type_pqc must be {oca_consts.OcaPqcSignatureType.ML_DSA_87.value:#04x} "
                f"(ML-DSA-87); got {sig_type:#x}",
                field_name="signature_type_pqc",
            )
        authority = _require(config, "signing_authority_pqc", context)
        if authority != "local":
            raise OcaConfigError(
                f"signing_authority_pqc must be 'local' for ML-DSA-87; got {authority!r}",
                field_name="signing_authority_pqc",
            )
        _require(config, "signing_key_file_pqc", context)
        select = int(_require(config, "public_key_select_pqc", context))
        if not (0 < select < (1 << 128)):
            raise OcaConfigError(
                f"public_key_select_pqc must be a non-zero 128-bit bitmask; got {select}",
                field_name="public_key_select_pqc",
            )
        out["signature_type_pqc"] = sig_type
        out["public_key_select_pqc"] = select
        out["signature_encoding_pqc"] = _pqc_encoding(config, "signature_encoding_pqc")
        out["public_key_encoding_pqc"] = _pqc_encoding(config, "public_key_encoding_pqc")

    revoke = int(config.get("public_key_pqc_revoke", 0))
    if revoke and manifest_format != "oca-pqc":
        raise OcaConfigError(
            "public_key_pqc_revoke is a PQC field, which only an oca-pqc manifest carries",
            field_name="public_key_pqc_revoke",
        )
    if not (0 <= revoke < (1 << 128)):
        raise OcaConfigError(
            f"public_key_pqc_revoke must fit in 128 bits; got {revoke}",
            field_name="public_key_pqc_revoke",
        )
    out["public_key_pqc_revoke"] = revoke if secure_boot == 1 else 0


def _is_printable_ascii(s: str) -> bool:
    """Printable ASCII = 0x20..0x7E inclusive, no NUL or DEL."""
    return all(0x20 <= ord(c) <= 0x7E for c in s)


def _check_group_code(value: int, *, shift: int, code: int, label: str, bits: str) -> None:
    """Enforce that a `signature_class_revoke` group-code byte is 0x00 or intact.

    A group code is a single constant, not a bitmask — an intact code disables
    every algorithm in its group. The device-side register accumulates by OR, so
    the interlock only holds if no manifest ever carries a FRAGMENT of a code:
    fragments from separate manifests would otherwise accumulate into an intact
    constant that no single manifest ever declared, revoking a whole group by
    increment rather than by intent.
    """
    actual = (value >> shift) & 0xFF
    if actual not in (0x00, code):
        raise OcaConfigError(
            f"signature_class_revoke {label} group code {bits} must be exactly 0x00 "
            f"or exactly {code:#04x}; got {actual:#04x}. A partial group code is not "
            f"a partial revocation — it carries no meaning and would accumulate into "
            f"an intact code in the device's OR-updated state.",
            field_name="signature_class_revoke",
        )


def _check_group_not_disabled_by_classes(value: int, *, classes_shift: int, defined: int,
                                         group_shift: int, label: str, bits: str) -> None:
    """Refuse a `signature_class_revoke` group whose every defined class bit is
    set while its group code byte is 0x00.

    Setting every class disables the whole group, which only the intact group
    code may do: disabling a group is meant to be the explicit act the code
    records.
    """
    classes = (value >> classes_shift) & 0xFF
    if classes & defined == defined and (value >> group_shift) & 0xFF == 0x00:
        raise OcaConfigError(
            f"signature_class_revoke sets every defined {label} class bit ({bits}) "
            f"without the {label} group code; disabling the whole group takes the "
            f"group code itself",
            field_name="signature_class_revoke",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_and_normalize_oca_classic(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the config and return a normalized dict with derived byte fields.

    Returns a dict containing fully-resolved values:
        manifest_identifier_bytes : bytes  (8 bytes, NUL-padded)
        description_bytes         : bytes  (128 bytes, NUL-terminated at byte 127)
        chiplet_id_bytes          : bytes  (32 bytes; unselected positions = 0xA5)
        package_id_bytes          : bytes  (32 bytes; unselected positions = 0xA5)
        system_id_bytes           : bytes  (32 bytes; unselected positions = 0xA5)
        selector_bits             : int    (128-bit integer)
        timestamp                 : int    (signed 64-bit)
        secure_boot               : int    (0 or 1; bit 0 of secure_boot_enforced)
        manifest_content_version  : (major, minor, patch) tuple
        ... plus the original config for any other fields the manifest builder reads.

    Raises OcaConfigError on validation failure.
    """
    out: Dict[str, Any] = {"_source": config}

    # manifest_identifier — required, 1-8 printable ASCII chars.
    ident = _require(config, "manifest_identifier")
    if not isinstance(ident, str):
        raise OcaConfigError(
            f"manifest_identifier must be a 1-8 ASCII character string for oca-classic, got {type(ident).__name__}",
            field_name="manifest_identifier",
        )
    if not (1 <= len(ident) <= oca_consts.MANIFEST_IDENTIFIER_MAX_TEXT):
        raise OcaConfigError(
            f"manifest_identifier must be 1-8 characters; got {len(ident)} characters",
            field_name="manifest_identifier",
        )
    if not _is_printable_ascii(ident):
        raise OcaConfigError(
            f"manifest_identifier must be printable ASCII only (no NUL, no high bytes)",
            field_name="manifest_identifier",
        )
    out["manifest_identifier_bytes"] = ident.encode("ascii").ljust(
        oca_consts.MANIFEST_IDENTIFIER_SIZE, b"\x00"
    )

    # description — required, ≤ 127 ASCII chars (byte 127 reserved for NUL).
    desc = _require(config, "description")
    if not isinstance(desc, str):
        raise OcaConfigError(
            f"description must be an ASCII string, got {type(desc).__name__}",
            field_name="description",
        )
    desc_bytes = desc.encode("ascii", errors="strict")
    if len(desc_bytes) > oca_consts.MANIFEST_DESCRIPTION_MAX_TEXT:
        raise OcaConfigError(
            f"description exceeds 127-character limit (got {len(desc_bytes)} bytes)",
            field_name="description",
        )
    out["description_bytes"] = desc_bytes.ljust(oca_consts.MANIFEST_DESCRIPTION_SIZE, b"\x00")

    # secure_boot — 0 or 1.
    sb = int(config.get("secure_boot", 0))
    if sb not in (0, 1):
        raise OcaConfigError(
            f"secure_boot must be 0 or 1; got {sb}",
            field_name="secure_boot",
        )
    out["secure_boot"] = sb

    manifest_format = config.get("manifest_format", "oca-classic")
    sb_classic, sb_pqc = _normalize_signature_classes(config, sb, manifest_format)
    out["secure_boot_classic"] = sb_classic
    out["secure_boot_pqc"] = sb_pqc
    if not sb_classic:
        _reject_fields_for_disabled_class(
            config, CLASSIC_SIGNING_FIELDS,
            "secure_boot_classic: 1" if sb == 1 else "secure_boot: 1")
    if sb_classic:
        _require(config, "signature_type", "the classical signature class")
        _require(config, "signing_authority", "the classical signature class")
    _normalize_pqc_signing(config, out, sb, sb_pqc, manifest_format)

    # public_key_select_classic — 16-byte (128-bit) bitmask. Required when the
    # classical class is enforced (≥ 1 bit must be set; otherwise no key is
    # authorized and secure boot would fail at the Consumer).
    pkscl = config.get("public_key_select_classic")
    if sb_classic:
        if pkscl is None:
            raise OcaConfigError(
                "missing required field for oca-classic secure_boot=1: public_key_select_classic",
                field_name="public_key_select_classic",
            )
        pkscl_int = int(pkscl)
        if not (0 < pkscl_int < (1 << 128)):
            raise OcaConfigError(
                f"public_key_select_classic must be a non-zero 128-bit bitmask when "
                f"secure_boot=1; got {pkscl_int}",
                field_name="public_key_select_classic",
            )
        out["public_key_select_classic"] = pkscl_int
    else:
        out["public_key_select_classic"] = 0

    # Encoding selectors for public-key and signature bytes — DER (0x01) or
    # raw bytes (0x02). Integrator-defined (0xF0-0xFF) is deferred.
    #
    # Both default to raw, because raw is the only encoding available for every
    # algorithm. DER is defined solely for RSA public keys and ECDSA signatures;
    # for anything else it has no defined structure, so defaulting to it would
    # hand most configurations an encoding the format does not define. Which
    # (type, encoding) pairs are legal is enforced in signing.py, where the
    # concrete key and signature are produced.
    pk_enc = _classic_encoding(config, "public_key_encoding")
    sig_enc = _classic_encoding(config, "signature_encoding")
    out["public_key_encoding"] = pk_enc if sb_classic else 0
    out["signature_encoding"] = sig_enc if sb_classic else 0

    # public_key_classic_revoke — 16-byte bitmask, default 0.
    pkrev = int(config.get("public_key_classic_revoke", 0))
    if not (0 <= pkrev < (1 << 128)):
        raise OcaConfigError(
            f"public_key_classic_revoke must fit in 128 bits; got {pkrev}",
            field_name="public_key_classic_revoke",
        )
    out["public_key_classic_revoke"] = pkrev if sb == 1 else 0

    # manifest_security_control — the six device-state update-disable bits:
    #   bit0 manifest-security-version   bit3 verifier-key-revoke
    #   bit1 ROOT-key-revoke             bit4 signature-cohort-enforce
    #   bit2 verifier-security-version   bit5 signature-class-revoke
    # Only bits [5:0] are defined; reject anything else.
    #
    # With the bits clear (0x00), a successful boot lets the Consumer OR this
    # manifest's declared revocations, security-version flags, and signature
    # posture into the device state — setting only the bits this manifest carries
    # that the device lacks, so it is a no-op when the manifest matches what the
    # device already has. Development/bring-up manifests set 0x3F to suppress
    # those automatic fuse updates while iterating.
    msc = int(config.get("manifest_security_control", 0))
    if not (0 <= msc <= oca_consts.MANIFEST_SECURITY_CONTROL_VALID_MASK):
        raise OcaConfigError(
            f"manifest_security_control must be in 0x00.."
            f"{oca_consts.MANIFEST_SECURITY_CONTROL_VALID_MASK:#04x} (six "
            f"update-disable bits); got {msc:#x}",
            field_name="manifest_security_control",
        )
    out["manifest_security_control"] = msc if sb == 1 else 0

    # signature_cohort_enforce — which signature cohorts (classical, PQC, or
    # both) must be present before the Consumer treats each signed entity as
    # verified. OR'd into device storage after a verified boot, so it governs
    # SUBSEQUENT boots rather than this one.
    #
    # Nibbles for the verifier key and co-signers are accepted even though both
    # features are deferred here: this is a device-state register describing the
    # posture a device should adopt going forward, not a claim about what the
    # current manifest carries. A Producer may legitimately raise the posture for
    # entities that later manifests will use.
    cohort = int(config.get("signature_cohort_enforce", 0))
    if not (0 <= cohort < (1 << 64)):
        raise OcaConfigError(
            f"signature_cohort_enforce must fit in 64 bits; got {cohort}",
            field_name="signature_cohort_enforce",
        )
    if cohort & oca_consts.SIGNATURE_COHORT_ENFORCE_RESERVED_MASK:
        raise OcaConfigError(
            f"signature_cohort_enforce sets reserved bits "
            f"({cohort & oca_consts.SIGNATURE_COHORT_ENFORCE_RESERVED_MASK:#x}); each "
            f"of the ten entity nibbles defines only bit0 (classical required) and "
            f"bit1 (PQC required), and only b[39:0] are assigned",
            field_name="signature_cohort_enforce",
        )
    out["signature_cohort_enforce"] = cohort if sb == 1 else 0

    # signature_class_revoke — algorithm classes that are no longer trusted.
    # Also OR'd into device storage after a verified boot.
    revoke = int(config.get("signature_class_revoke", 0))
    if not (0 <= revoke < (1 << 64)):
        raise OcaConfigError(
            f"signature_class_revoke must fit in 64 bits; got {revoke}",
            field_name="signature_class_revoke",
        )
    if revoke & oca_consts.SIGNATURE_CLASS_REVOKE_RESERVED_MASK:
        raise OcaConfigError(
            f"signature_class_revoke sets reserved bits "
            f"({revoke & oca_consts.SIGNATURE_CLASS_REVOKE_RESERVED_MASK:#x}); "
            f"b[23:16] and b[63:40] are reserved",
            field_name="signature_class_revoke",
        )
    _check_group_code(
        revoke,
        shift=oca_consts.SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_SHIFT,
        code=oca_consts.SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_CODE,
        label="classical", bits="b[15:8]",
    )
    _check_group_code(
        revoke,
        shift=oca_consts.SIGNATURE_CLASS_REVOKE_PQC_GROUP_SHIFT,
        code=oca_consts.SIGNATURE_CLASS_REVOKE_PQC_GROUP_CODE,
        label="PQC", bits="b[39:32]",
    )
    _check_group_not_disabled_by_classes(
        revoke,
        classes_shift=oca_consts.SIGNATURE_CLASS_REVOKE_CLASSIC_CLASSES_SHIFT,
        defined=oca_consts.SIGNATURE_CLASS_REVOKE_CLASSIC_DEFINED_CLASSES,
        group_shift=oca_consts.SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_SHIFT,
        label="classical", bits="b[7:0]",
    )
    _check_group_not_disabled_by_classes(
        revoke,
        classes_shift=oca_consts.SIGNATURE_CLASS_REVOKE_PQC_CLASSES_SHIFT,
        defined=oca_consts.SIGNATURE_CLASS_REVOKE_PQC_DEFINED_CLASSES,
        group_shift=oca_consts.SIGNATURE_CLASS_REVOKE_PQC_GROUP_SHIFT,
        label="PQC", bits="b[26:24], b[30:28] and b31",
    )
    out["signature_class_revoke"] = revoke if sb == 1 else 0

    # Payload encryption — accept the supported path (AES-256-CBC or AES-128-CBC,
    # key derived from a pre-shared secret via SP 800-108r1 CTR-HMAC-SHA-256 over the
    # expanded input block) and record normalized values for the manifest builder.
    # Deferred sub-features (KEM, other ciphers/KDFs, aws/hsm authority) are
    # rejected in reject_deferred_features before we reach here.
    enc_on = int(config.get("encrypted_payload", 0) or 0) == 1
    if enc_on:
        if sb != 1:
            raise OcaConfigError(
                "encrypted_payload=1 requires secure_boot=1",
                field_name="encrypted_payload",
            )
        out["encrypted_payload"] = 1
        # encryption_type SHOULD be specified explicitly in the config; when
        # omitted it defaults to the stronger AES-256-CBC (never the weaker
        # AES-128-CBC).
        out["encryption_type"] = int(
            config.get("encryption_type", oca_consts.OcaEncryptionType.AES_256_CBC.value)
        )
        out["encryption_kdf"] = int(
            config.get("encryption_key_derivation_function",
                       oca_consts.OcaEncryptionKdf.SP800_108_CTR_HMAC_SHA256.value)
        )
        # Shared-secret indices start at 1 (0 means "unspecified"); default to
        # the first slot when omitted.
        sss = int(config.get("encryption_shared_secret_select", 1))
        if not (1 <= sss < (1 << 16)):
            raise OcaConfigError(
                f"encryption_shared_secret_select must be 1..65535 "
                f"(indices start at 1); got {sss}",
                field_name="encryption_shared_secret_select",
            )
        out["encryption_shared_secret_select"] = sss
    else:
        out["encrypted_payload"] = 0

    # usage_constraints — delegate the entire control-plane block to the
    # dedicated decoder module. The decoder produces every key the manifest
    # builder reads (identity bytes, lifecycle states, version-range bytes,
    # demotion_control, selector_bits) from either ergonomic or raw inputs.
    from . import usage_constraints
    out.update(usage_constraints.decode(config.get("usage_constraints") or {}, secure_boot=sb))

    # timestamp — explicit int from config, or current wall-clock seconds.
    ts = config.get("timestamp")
    if ts is None:
        import time
        ts = int(time.time())
    else:
        ts = int(ts)
    out["timestamp"] = ts

    # manifest_content_version — default 0.0.0.
    mcv = config.get("manifest_content_version") or {}
    out["manifest_content_version"] = (
        int(mcv.get("major", 0)),
        int(mcv.get("minor", 0)),
        int(mcv.get("patch", 0)),
    )

    # payload_images — must have at least one entry for OCA-classic.
    images = config.get("payload_images") or []
    if not images:
        raise OcaConfigError(
            "payload_images must contain at least one image for oca-classic",
            field_name="payload_images",
        )
    out["payload_images"] = images

    return out


def reject_deferred_features(config: Dict[str, Any]) -> None:
    """Raise OcaConfigError for any config that enables an OCA capability the
    packer does not support yet.

    Checked features:
      - PQC signature algorithms other than ML-DSA-87 (0x33), and an ML-DSA
        signing authority other than `local`
      - Payload encryption fields
      - Verifier-key entry fields
      - Co-signer entries
      - Signature algorithms outside {0x01, 0x05}
      - Hash algorithms outside {0x01} (SHA-256)
      - HSM signing authority

    Designed to run BEFORE validate_and_normalize_oca_classic so deferred
    features fail fast with their *named feature* rather than a downstream
    type-shape error.
    """
    # Format selector. 'oca-combined' never reaches here — pack_images dispatches it
    # to the combined-image builder before the per-manifest path. Anything else is a
    # typo or an unimplemented variant, not a named deferred feature, so it renders
    # as a plain error rather than a "deferred to future pass" message.
    fmt = config.get("manifest_format")
    if fmt is not None and fmt not in ("oca-classic", "oca-pqc"):
        raise OcaConfigError(
            f"unknown manifest_format {fmt!r}; expected 'oca-classic' "
            f"or 'oca-pqc'",
            field_name="manifest_format",
        )

    # PQC signature algorithm and authority. Of the PQC algorithms the packer
    # supports ML-DSA-87 alone, and it signs through `local` only. Checked
    # whatever secure_boot says, so an unsupported request is named before any
    # class rule fires.
    if _truthy(config, "signature_type_pqc") and \
            int(config["signature_type_pqc"]) != oca_consts.OcaPqcSignatureType.ML_DSA_87.value:
        raise OcaConfigError(
            "OCA feature deferred to future pass: Unsupported signature algorithm "
            "(field signature_type_pqc)",
            field_name="signature_type_pqc",
            deferred_feature="Unsupported signature algorithm",
        )
    for authority, label in (("aws", "AWS signing authority for ML-DSA"),
                             ("hsm", "HSM signing authority")):
        if config.get("signing_authority_pqc") == authority:
            raise OcaConfigError(
                f"OCA feature deferred to future pass: {label} (field signing_authority_pqc)",
                field_name="signing_authority_pqc",
                deferred_feature=label,
            )

    # Payload encryption. The supported path — AES-256-CBC or AES-128-CBC with a key
    # derived from a pre-shared secret via SP 800-108r1 over the expanded input block
    # — is accepted and validated in validate_and_normalize_oca_classic. Here we fail
    # fast on the pieces that remain deferred: KEM key-wrapping, any other cipher /
    # KDF, and remote (aws / hsm) encryption authorities.
    for fname in ("encryption_kem_dek", "encryption_key_encapsulation_function",
                  "encryption_kem_unwrap_key_select"):
        if _truthy(config, fname):
            raise OcaConfigError(
                f"OCA feature deferred to future pass: KEM key wrapping (field {fname})",
                field_name=fname,
                deferred_feature="KEM key wrapping",
            )
    if _truthy(config, "encrypted_payload"):
        etype = config.get("encryption_type")
        if etype is not None and int(etype) not in oca_consts.ENCRYPTION_TYPES_SUPPORTED:
            raise OcaConfigError(
                "OCA feature deferred to future pass: Unsupported encryption algorithm "
                "(field encryption_type)",
                field_name="encryption_type",
                deferred_feature="Unsupported encryption algorithm",
            )
        ekdf = config.get("encryption_key_derivation_function")
        if ekdf is not None and \
                int(ekdf) != oca_consts.OcaEncryptionKdf.SP800_108_CTR_HMAC_SHA256.value:
            raise OcaConfigError(
                "OCA feature deferred to future pass: Unsupported key-derivation function "
                "(field encryption_key_derivation_function)",
                field_name="encryption_key_derivation_function",
                deferred_feature="Unsupported key-derivation function",
            )
    enc_authority = config.get("encryption_authority")
    if enc_authority in ("aws", "hsm"):
        label = f"{enc_authority.upper()} encryption authority"
        raise OcaConfigError(
            f"OCA feature deferred to future pass: {label} (field encryption_authority)",
            field_name="encryption_authority",
            deferred_feature=label,
        )

    # Verifier-key entry and co-signer entries.
    #
    # Swept by prefix rather than by an enumerated list of field names. Both
    # entry types carry a large and growing family of fields — ROOT-authorized
    # copies, per-entry key/signature/encoding/size fields, delegation controls —
    # and an enumerated list silently accepts every field the format gains after
    # the list was written, which is exactly how a config asking for a deferred
    # feature would slip through un-validated. No supported config key begins with
    # either prefix, so the sweep cannot over-reject.
    #
    # `sorted()` so a config naming several deferred fields always reports the
    # same one.
    for fname in sorted(config):
        for prefix, label in (("verifier_", "Verifier-key entry"),
                              ("co_signer_", "Co-signer entries")):
            if fname.startswith(prefix) and _truthy(config, fname):
                raise OcaConfigError(
                    f"OCA feature deferred to future pass: {label} (field {fname})",
                    field_name=fname,
                    deferred_feature=label,
                )

    if _truthy(config, "use_verifier_key"):
        raise OcaConfigError(
            "OCA feature deferred to future pass: Verifier-key entry "
            "(field use_verifier_key)",
            field_name="use_verifier_key",
            deferred_feature="Verifier-key entry",
        )
    if config.get("co_signers"):
        raise OcaConfigError(
            "OCA feature deferred to future pass: Co-signer entries (field co_signers)",
            field_name="co_signers",
            deferred_feature="Co-signer entries",
        )

    # Signature algorithm.
    if config.get("secure_boot"):
        sig_type = config.get("signature_type")
        if sig_type is not None:
            sig_type_int = int(sig_type)
            allowed = {
                oca_consts.OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value,
                oca_consts.OcaClassicSignatureType.ECDSA_P256_SHA256.value,
            }
            if sig_type_int not in allowed:
                raise OcaConfigError(
                    f"OCA feature deferred to future pass: Unsupported signature algorithm "
                    f"(field signature_type)",
                    field_name="signature_type",
                    deferred_feature="Unsupported signature algorithm",
                )

    # Hash algorithms.
    for fname in ("manifest_hash_type", "payload_hash_type"):
        v = config.get(fname)
        if v is not None and int(v) != oca_consts.OcaClassicHashType.SHA2_256.value:
            raise OcaConfigError(
                f"OCA feature deferred to future pass: Hash algorithms beyond SHA-256 "
                f"(field {fname})",
                field_name=fname,
                deferred_feature="Hash algorithms beyond SHA-256",
            )

    # HSM signing authority.
    sa = config.get("signing_authority")
    if sa == "hsm":
        raise OcaConfigError(
            "OCA feature deferred to future pass: HSM signing authority "
            "(field signing_authority)",
            field_name="signing_authority",
            deferred_feature="HSM signing authority",
        )


def _truthy(config: Dict[str, Any], key: str) -> bool:
    """Return True if `config[key]` is set to a non-default 'active' value.

    Used by reject_deferred_features to detect when a producer is *enabling*
    a deferred feature (vs. just naming it with a zero/empty value). For ints,
    nonzero is active; for strings, non-empty is active; for lists, non-empty
    is active.
    """
    if key not in config:
        return False
    v = config[key]
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, (str, bytes, list, tuple)):
        return len(v) > 0
    if v is None:
        return False
    return True

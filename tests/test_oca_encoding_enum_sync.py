"""Drift gate: the C validator's `oca_encoding_t` must mirror the packer's
encoding byte values exactly.

`oca_signature_check()` casts the manifest's `signature_encoding_classic` and
`public_key_encoding_classic` bytes straight to `oca_encoding_t` with no
translation. That is only sound while the enumerator values ARE the on-disk byte
values, so this file pins that correspondence.

Why a dedicated gate rather than `sync_layout.py`: that script parses `#define`s
out of the `oca_layout*.h` headers, and this is an `enum` in `oca_validator.h`.
It followed the same pattern as `test_pqc_layout_anchors_match_python_constants`
— a script-independent guard that parses the header directly.

The failure this prevents actually happened. The enum was originally
`{RAW = 0, DER = 1}`, which:

  * aliased "field never populated" (0x00, what a `secure_boot = 0` bundle
    carries) onto a real encoding, RAW;
  * left the format's raw-little-endian value (0x02) with no enumerator at all,
    so a legitimate, spec-legal manifest cast a byte the type did not define;
  * matched DER only by coincidence, 0x01 lining up with the second enumerator.

Casting an out-of-range byte to an enum is well-defined in C — the value is
representable in the implementation-chosen underlying type — so `-fsanitize=enum`
stays quiet under `-std=c99`. It is undefined behaviour in C++, which
`oca_validator.h` invites via its `extern "C"` guard.
"""

from __future__ import annotations

import os
import re

import pytest

from tt_boot_manifest.oca import constants as oca_consts


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALIDATOR_HEADER = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "oca_validator.h"
)

# `    OCA_ENCODING_DER    = 0x01,`
_ENUMERATOR_RE = re.compile(
    r"^\s*(?P<name>OCA_ENCODING_\w+)\s*=\s*(?P<value>0x[0-9A-Fa-f]+|\d+)\s*,?\s*$"
)

# C enumerator -> packer enum member. Both encoding enums (signature and public
# key) share one value set, so the signature one stands in for both; a separate
# test below asserts they have not diverged.
_EXPECTED_MEMBERS = {
    "OCA_ENCODING_UNSET": "UNSET",
    "OCA_ENCODING_DER": "ASN1_DER",
    "OCA_ENCODING_RAW": "RAW_BYTES",
}


def _parse_oca_encoding_enum() -> dict[str, int]:
    """Return {enumerator: value} for the `oca_encoding_t` enum body."""
    with open(VALIDATOR_HEADER) as handle:
        text = handle.read()

    match = re.search(
        r"typedef\s+enum\s+oca_encoding\s*\{(?P<body>.*?)\}\s*oca_encoding_t\s*;",
        text,
        re.DOTALL,
    )
    assert match, f"oca_encoding_t enum not found in {VALIDATOR_HEADER}"

    found: dict[str, int] = {}
    for line in match.group("body").splitlines():
        enumerator = _ENUMERATOR_RE.match(line)
        if enumerator:
            found[enumerator.group("name")] = int(enumerator.group("value"), 0)
    return found


def test_c_encoding_enum_values_match_the_packer():
    """Every C enumerator equals the packer byte value it mirrors."""
    c_enum = _parse_oca_encoding_enum()
    for c_name, py_member in _EXPECTED_MEMBERS.items():
        assert c_name in c_enum, (
            f"{c_name} missing from oca_encoding_t in oca_validator.h — the C "
            f"validator can no longer represent "
            f"OcaClassicSignatureEncoding.{py_member}"
        )
        expected = oca_consts.OcaClassicSignatureEncoding[py_member].value
        assert c_enum[c_name] == expected, (
            f"{c_name} = {c_enum[c_name]:#04x} in oca_validator.h but "
            f"OcaClassicSignatureEncoding.{py_member} = {expected:#04x}. "
            f"The validator casts the manifest byte straight to oca_encoding_t, "
            f"so these must be equal."
        )


def test_c_encoding_enum_covers_every_value_the_packer_can_emit():
    """No producible byte may land outside the enum.

    This is the invariant that broke before: raw-little-endian (0x02) was
    emittable with no enumerator to receive it.
    """
    c_values = set(_parse_oca_encoding_enum().values())
    for member in oca_consts.OcaClassicSignatureEncoding:
        assert member.value in c_values, (
            f"the packer can write signature_encoding_classic = "
            f"{member.value:#04x} ({member.name}) but oca_encoding_t has no "
            f"enumerator for it; casting that byte is undefined behaviour in C++ "
            f"and yields a value no consumer can interpret"
        )


def test_c_encoding_enum_has_no_values_the_packer_cannot_emit():
    """The reverse direction: an enumerator with no packer counterpart means the
    C side is describing an encoding this producer never writes, which is how the
    original RAW = 0 aliasing slipped in."""
    py_values = {member.value for member in oca_consts.OcaClassicSignatureEncoding}
    for c_name, c_value in _parse_oca_encoding_enum().items():
        assert c_value in py_values, (
            f"{c_name} = {c_value:#04x} in oca_encoding_t has no counterpart in "
            f"OcaClassicSignatureEncoding; either the packer gained an encoding "
            f"without a constant, or the C enum invented one"
        )


def test_signature_and_public_key_encodings_share_one_value_set():
    """The two manifest fields are specified with the same value set, and the C
    side models both with a single `oca_encoding_t`. If they ever diverge, that
    single type stops being correct for both."""
    signature = {m.name: m.value for m in oca_consts.OcaClassicSignatureEncoding}
    public_key = {m.name: m.value for m in oca_consts.OcaClassicPublicKeyEncoding}
    assert signature == public_key, (
        "OcaClassicSignatureEncoding and OcaClassicPublicKeyEncoding have "
        "diverged; oca_encoding_t in the C validator models both with one type"
    )


def test_unset_is_distinct_from_every_real_encoding():
    """0x00 means "field never populated" (secure_boot = 0 zeroes the signing
    fields). It must not double as a real encoding — that aliasing is precisely
    the bug this gate exists to prevent."""
    unset = oca_consts.OcaClassicSignatureEncoding.UNSET.value
    assert unset == 0x00
    assert unset not in oca_consts.OCA_SELECTABLE_ENCODINGS, (
        "UNSET leaked into the selectable-encoding set; a config could then "
        "request it and produce a signed bundle claiming no encoding"
    )


@pytest.mark.parametrize("encoding", list(oca_consts.OCA_SELECTABLE_ENCODINGS))
def test_selectable_encodings_are_accepted_by_the_validator_config_path(encoding):
    """Each selectable encoding survives config validation, so the value set the
    gate above pins is the value set a producer can actually use."""
    from tt_boot_manifest.oca.validators import validate_and_normalize_oca_classic

    config = {
        "manifest_identifier": "ENCCHK",
        "description": "encoding round-trip",
        "secure_boot": 1,
        "public_key_select_classic": 0x01,
        "signature_encoding": encoding,
        "public_key_encoding": encoding,
        "payload_images": [{"path": "examples/oca_classic_basic/dummy_image.bin"}],
    }
    normalized = validate_and_normalize_oca_classic(config)
    assert normalized["signature_encoding"] == encoding
    assert normalized["public_key_encoding"] == encoding


# ---------------------------------------------------------------------------
# oca_encryption_type_t <-> OcaEncryptionType
#
# The same class of gate, for the other on-disk enum the validator casts a
# manifest byte to. `check_encrypted_payload()` compares
# `body[OFF_ENCRYPTION_TYPE]` against these enumerators to decide whether the
# cipher is one it implements, and passes the value on to the decryption callback
# as a typed `oca_decrypt_input_t::cipher` — so a divergence would both misjudge
# the support gate and mislead the callback.
#
# The encoding gate above does not cover this enum. Nothing about it had gone
# wrong; it was simply missed.
# ---------------------------------------------------------------------------

VALIDATOR_PAYLOAD = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "payload.c"
)

# Tolerates a trailing `/**< ... */` doc comment, deliberately. The encoding gate
# above does not, which is why `oca_encoding_t` has to document each enumerator on
# the PRECEDING line — a formatting constraint imposed by a parser rather than by
# anything about the code. Not worth propagating to a second enum.
_ENC_TYPE_RE = re.compile(
    r"^\s*(?P<name>OCA_ENCRYPTION_TYPE_\w+)\s*=\s*(?P<value>0x[0-9A-Fa-f]+|\d+)"
    r"\s*,?\s*(?:/\*.*)?$"
)

# The byte an unencrypted manifest carries. The packer writes it as a literal
# `enc.get("type", 0)` default rather than an enum member, so it has no
# OcaEncryptionType counterpart and has to be named here instead.
_UNENCRYPTED_BYTE = 0x00


def _parse_oca_encryption_type_enum() -> dict[str, int]:
    """Return {enumerator: value} for the `oca_encryption_type_t` enum body."""
    with open(VALIDATOR_HEADER) as handle:
        text = handle.read()

    match = re.search(
        r"typedef\s+enum\s+oca_encryption_type\s*\{(?P<body>.*?)\}"
        r"\s*oca_encryption_type_t\s*;",
        text,
        re.DOTALL,
    )
    assert match, f"oca_encryption_type_t enum not found in {VALIDATOR_HEADER}"

    found: dict[str, int] = {}
    for line in match.group("body").splitlines():
        enumerator = _ENC_TYPE_RE.match(line)
        if enumerator:
            found[enumerator.group("name")] = int(enumerator.group("value"), 0)
    return found


def _parse_c_supported_ciphers() -> set[str]:
    """Enumerator names the C cipher gate accepts.

    Reads the rejection in `check_encrypted_payload()` rather than trusting a
    comment: the gate is written as "not this and not that -> refuse", so the
    names appearing in it are exactly the ciphers the validator implements.
    """
    with open(VALIDATOR_PAYLOAD) as handle:
        text = handle.read()

    match = re.search(
        r"uint8_t enc_type = body\[OCA_OFF_ENCRYPTION_TYPE\];\s*"
        r"if\s*\((?P<cond>.*?)\)\s*\{",
        text,
        re.DOTALL,
    )
    assert match, (
        f"the encryption_type support gate was not found in {VALIDATOR_PAYLOAD}; "
        f"if it moved or changed shape, update this parser rather than deleting "
        f"the test — the gate is what keeps an unimplemented cipher away from the "
        f"ciphertext"
    )
    return set(re.findall(r"OCA_ENCRYPTION_TYPE_\w+", match.group("cond")))


def test_c_encryption_type_values_match_the_packer():
    """Every packer cipher has a C enumerator with the same byte value."""
    c_enum = _parse_oca_encryption_type_enum()
    by_value = {value: name for name, value in c_enum.items()}
    for member in oca_consts.OcaEncryptionType:
        assert member.value in by_value, (
            f"the packer can write encryption_type = {member.value:#04x} "
            f"({member.name}) but oca_encryption_type_t has no enumerator for "
            f"it; the validator casts that byte straight to the enum and hands "
            f"it to the decryption callback"
        )


def test_c_encryption_type_covers_every_value_the_packer_can_emit():
    """Including the unencrypted default, which is a literal 0 in the packer
    rather than an enum member — so it is the value most likely to be forgotten
    on either side."""
    c_values = set(_parse_oca_encryption_type_enum().values())
    emittable = {_UNENCRYPTED_BYTE} | {
        member.value for member in oca_consts.OcaEncryptionType
    }
    missing = emittable - c_values
    assert not missing, (
        f"the packer can emit encryption_type {sorted(hex(v) for v in missing)} "
        f"with no oca_encryption_type_t enumerator to receive it"
    )


def test_c_encryption_type_has_no_values_the_packer_cannot_emit():
    """The reverse direction: an enumerator the producer never writes means the C
    side is describing a cipher this pipeline cannot produce."""
    emittable = {_UNENCRYPTED_BYTE} | {
        member.value for member in oca_consts.OcaEncryptionType
    }
    for c_name, c_value in _parse_oca_encryption_type_enum().items():
        assert c_value in emittable, (
            f"{c_name} = {c_value:#04x} in oca_encryption_type_t has no "
            f"counterpart the packer can write; either the packer lost a cipher "
            f"or the C enum invented one"
        )


def test_c_cipher_gate_matches_the_packer_supported_set():
    """The set of ciphers the validator implements must equal the set the packer
    considers supported.

    Two independent statements of one fact — the C gate in
    `check_encrypted_payload()` and `ENCRYPTION_TYPES_SUPPORTED` — and a
    divergence is silent in both directions: a cipher the packer will happily
    encrypt with but the validator refuses, or one the validator would accept
    that no producer can make.
    """
    c_enum = _parse_oca_encryption_type_enum()
    gate_names = _parse_c_supported_ciphers()
    c_supported = {c_enum[name] for name in gate_names}
    assert c_supported == set(oca_consts.ENCRYPTION_TYPES_SUPPORTED), (
        f"the C validator implements ciphers "
        f"{sorted(hex(v) for v in c_supported)} but the packer's "
        f"ENCRYPTION_TYPES_SUPPORTED is "
        f"{sorted(hex(v) for v in oca_consts.ENCRYPTION_TYPES_SUPPORTED)}"
    )


def test_unencrypted_byte_is_not_a_supported_cipher():
    """0x00 means "no encryption", not a cipher. The validator's gate must refuse
    it, so that a manifest with the encrypted bit set but the type left zero is
    rejected rather than routed to a decryption backend with no cipher."""
    assert _UNENCRYPTED_BYTE not in oca_consts.ENCRYPTION_TYPES_SUPPORTED
    c_enum = _parse_oca_encryption_type_enum()
    gate = {c_enum[name] for name in _parse_c_supported_ciphers()}
    assert _UNENCRYPTED_BYTE not in gate, (
        "the C cipher gate accepts 0x00; an encrypted-bit manifest with "
        "encryption_type = 0 would reach the decryption callback"
    )

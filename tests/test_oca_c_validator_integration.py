# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""End-to-end integration tests: the C validator CLI against bundles
produced by the Python packer.

These tests build the CLI on demand (a single shared `make` invocation
per pytest run), then drive it as a subprocess against the YAML fixtures
under validators/oca/test/fixtures/configs/. They cover the
happy-path PASS for every fixture plus the documented FAIL paths
(tamper, bad magic, truncation, missing flag, usage error).
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import tomllib

import pytest

from tt_boot_manifest.oca import constants as oca_constants
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.signing import (build_pqc_signing_key, build_signing_key,
                                          sign_signed_region, sign_signed_region_pqc)
from tt_boot_manifest.utils import load_config


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALIDATOR_DIR = os.path.join(PROJECT_ROOT, "validators", "oca")
CLI_PATH = os.path.join(VALIDATOR_DIR, "build", "test", "oca-validate")
FIXTURE_DIR = os.path.join(VALIDATOR_DIR, "test", "fixtures", "configs")
FIXTURE_BUILD = os.path.join(VALIDATOR_DIR, "build", "fixtures")

PASS_RE = re.compile(rb"^PASS: \w+ v\d+\.\d+\.\d+\n$")


# Set in CI, where a missing prerequisite must fail the run rather than shrink
# the suite.
REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"


def _openssl_min_version() -> str:
    """OPENSSL_MIN_VERSION from the validator Makefile, where it is set."""
    with open(os.path.join(VALIDATOR_DIR, "Makefile")) as f:
        return re.search(r"^OPENSSL_MIN_VERSION \?= (\S+)$", f.read(), re.M).group(1)


def _validator_unavailable_reason():
    """Why this host cannot build the CLI, or None when it can."""
    if shutil.which("make") is None or shutil.which("pkg-config") is None:
        return "make + pkg-config required to build the OCA validator CLI"
    minimum = _openssl_min_version()
    if (subprocess.run(["pkg-config", "--exists", "openssl"]).returncode == 0
            and subprocess.run(["pkg-config", f"--atleast-version={minimum}",
                                "openssl"]).returncode != 0):
        found = subprocess.run(["pkg-config", "--modversion", "openssl"],
                               capture_output=True, text=True).stdout.strip()
        return (f"the OCA validator CLI needs OpenSSL {minimum} or later for "
                f"ML-DSA; pkg-config reports {found}")
    return None


@pytest.fixture(scope="module", autouse=True)
def build_cli():
    """Build the CLI once per test module."""
    reason = _validator_unavailable_reason()
    if reason is not None:
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)
    result = subprocess.run(
        ["make", "-C", VALIDATOR_DIR, "test"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHON": sys.executable},
    )
    if result.returncode != 0:
        pytest.fail(
            f"oca-validate build failed:\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    assert os.path.exists(CLI_PATH)


def _pack_fixture(name: str) -> str:
    """Run the Python packer to produce a bundle for the given fixture."""
    os.makedirs(FIXTURE_BUILD, exist_ok=True)
    out_path = os.path.join(FIXTURE_BUILD, f"{name}.bin")
    cfg_path = os.path.join(FIXTURE_DIR, f"{name}.yaml")
    cfg_rel = os.path.relpath(cfg_path, PROJECT_ROOT)
    out_rel = os.path.relpath(out_path, PROJECT_ROOT)
    result = subprocess.run(
        [sys.executable, "-m", "tt_boot_manifest.pack_images",
         "--config", cfg_rel, "--out", out_rel],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"packer failed for {name}: {result.stderr}")
    return out_path


def _read_flags(name: str) -> list[str]:
    flags_path = os.path.join(FIXTURE_DIR, f"{name}.flags")
    if not os.path.exists(flags_path):
        return []
    with open(flags_path) as f:
        content = f.read().strip()
    return content.split() if content else []


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [CLI_PATH, *args],
        capture_output=True,
    )


def _gated_cli(target: str) -> str:
    """Build a variant-gated CLI (`classic-only` / `pqc-only` / `both`) and
    return the path to its binary. Idempotent — `make` is a no-op once built."""
    result = subprocess.run(
        ["make", "-C", VALIDATOR_DIR, target],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHON": sys.executable},
    )
    if result.returncode != 0:
        pytest.fail(
            f"gated build '{target}' failed:\nstdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    cli = os.path.join(VALIDATOR_DIR, "build", target, "test", "oca-validate")
    assert os.path.exists(cli), f"gated CLI not found at {cli}"
    return cli


def _run_cli_at(cli: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([cli, *args], capture_output=True)


# ---------------------------------------------------------------------------
# PASS path: every fixture validates clean
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    ["basic", "control_plane", "secure_rsa", "secure_ecdsa", "all_constraints",
     "pqc_basic", "pqc_secure_rsa", "encrypted_aes", "encrypted_aes_pqc",
     "multi_image", "secure_rsa_e3", "secure_rsa_der", "secure_rsa_e3_der",
     "pqc_secure_mldsa", "pqc_hybrid_rsa", "pqc_hybrid_ecdsa", "encrypted_aes_pqc_mldsa"],
)
def test_cli_pass_for_each_fixture(fixture):
    bin_path = _pack_fixture(fixture)
    flags = _read_flags(fixture)
    result = _run_cli(["--manifest", bin_path, *flags])
    assert result.returncode == 0, (
        f"expected PASS for {fixture}; got exit {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert PASS_RE.match(result.stdout), (
        f"stdout does not match PASS regex: {result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# RSA public exponents: F4 (65537) and the legacy 3
#
# The signature length is fixed by the modulus, so the exponent only shows up in
# the public key — and only the DER encoding's LENGTH changes with it (396 at
# e=3, 398 at F4). These drive the C validator's two key-parsing paths with both
# exponents: reconstructing a raw key from its trailing 4-byte exponent, and
# parsing a PKCS#1 structure whose length is not known in advance.
# ---------------------------------------------------------------------------


_RSA_EXPONENT_FIXTURES = [
    # (fixture, exponent, key encoding, expected public_key_size_classic)
    ("secure_rsa",        65537, 0x02, 388),
    ("secure_rsa_e3",         3, 0x02, 388),
    ("secure_rsa_der",    65537, 0x01, 398),
    ("secure_rsa_e3_der",     3, 0x01, 396),
]


@pytest.mark.parametrize("fixture,exponent,encoding,key_size", _RSA_EXPONENT_FIXTURES)
def test_cli_verifies_signatures_across_rsa_exponents(
    fixture, exponent, encoding, key_size
):
    """The C validator verifies an RSA signature for both exponents under both
    key encodings, and the manifest describes the key the way we expect."""
    bin_path = _pack_fixture(fixture)
    with open(bin_path, "rb") as fh:
        body = fh.read(oca_constants.OCA_CLASSIC_BODY_SIZE)

    assert body[oca_constants.OFF_PUBLIC_KEY_ENCODING_CLASSIC] == encoding
    assert struct.unpack_from(
        "<H", body, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0] == key_size
    # The signature length never moves — it follows the modulus, not the exponent.
    assert struct.unpack_from(
        "<H", body, oca_constants.OFF_SIGNATURE_SIZE_CLASSIC)[0] == 384

    encoded = body[oca_constants.OFF_PUBLIC_KEY_CLASSIC:
                   oca_constants.OFF_PUBLIC_KEY_CLASSIC + key_size]
    if encoding == 0x02:
        # Raw: big-endian modulus then a 4-byte big-endian exponent.
        assert int.from_bytes(
            encoded[oca_constants.RSA_3072_MODULUS_BYTES:], "big") == exponent

    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key"])
    assert result.returncode == 0, (
        f"{fixture} (e={exponent}, encoding={encoding:#04x}) was rejected; "
        f"exit {result.returncode}\nstdout: {result.stdout!r}\n"
        f"stderr: {result.stderr!r}"
    )
    assert PASS_RE.match(result.stdout), result.stdout


def test_der_key_length_differs_between_rsa_exponents():
    """Premise for the DER cases above: the two exponents really do produce
    different key lengths. If they ever stopped, those cases would still pass
    while testing nothing about variable-length key parsing."""
    sizes = {}
    for fixture in ("secure_rsa_der", "secure_rsa_e3_der"):
        with open(_pack_fixture(fixture), "rb") as fh:
            body = fh.read(oca_constants.OCA_CLASSIC_BODY_SIZE)
        sizes[fixture] = struct.unpack_from(
            "<H", body, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    assert sizes["secure_rsa_der"] != sizes["secure_rsa_e3_der"], sizes


@pytest.mark.parametrize("fixture", ["secure_rsa_der", "secure_rsa_e3_der"])
def test_a_tampered_der_key_size_is_caught_by_manifest_integrity(fixture, tmp_path):
    """Editing public_key_size_classic is caught before anything parses the key.

    Worth pinning because of what the library does NOT do here. A raw key's
    length is fixed by the algorithm, so the size field is checked against a
    constant. A PKCS#1 key's length varies with the exponent — that is the whole
    reason the field exists — so the library can only bound it by the field, not
    predict it, and a value two bytes off is not intrinsically detectable.

    What protects it is placement: the field sits inside the signed region, so
    any edit breaks manifest_hash first. That is the stronger guarantee, and it
    is the one a consumer actually relies on.
    """
    with open(_pack_fixture(fixture), "rb") as fh:
        bundle = bytearray(fh.read())
    declared = struct.unpack_from(
        "<H", bundle, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    assert (oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC
            < oca_constants.OCA_CLASSIC_SIGNED_REGION_END), \
        "the size field must lie inside the signed region for this to hold"
    struct.pack_into("<H", bundle, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC,
                     declared + 2)

    result = _validate_bundle(bytes(bundle), tmp_path, f"{fixture}_badsize")
    assert result.returncode == 1, (
        f"expected rejection; got exit {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert re.match(rb"^FAIL: MANIFEST_HASH: ", result.stderr), result.stderr


def test_cli_pass_pqc_bundle():
    """A packer-produced (unsigned) PQC bundle round-trips through the
    validator: magic OCAP, 36864-byte body, structural PASS."""
    bin_path = _pack_fixture("pqc_basic")
    with open(bin_path, "rb") as f:
        head = f.read(4)
    assert head == b"OCAP", f"expected OCAP magic, got {head!r}"
    result = _run_cli(["--manifest", bin_path])
    assert result.returncode == 0, (
        f"expected PASS for PQC bundle; got exit {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert PASS_RE.match(result.stdout), (
        f"stdout does not match PASS regex: {result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# Shipped secure-boot example config: builds AND validates end-to-end, with
# ROOT-key revocation + anti-rollback security version + device-state controls.
# ---------------------------------------------------------------------------


def _pack_config(cfg_rel: str, out_name: str) -> str:
    """Pack an arbitrary repo-relative config path to a build-output bundle."""
    os.makedirs(FIXTURE_BUILD, exist_ok=True)
    out_path = os.path.join(FIXTURE_BUILD, f"{out_name}.bin")
    out_rel = os.path.relpath(out_path, PROJECT_ROOT)
    result = subprocess.run(
        [sys.executable, "-m", "tt_boot_manifest.pack_images",
         "--config", cfg_rel, "--out", out_rel],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"packer failed for {cfg_rel}: {result.stderr}")
    return out_path


def test_secure_boot_device_state_example_builds_and_validates():
    """The shipped device-state secure-boot example config packs with its
    device-state fields set, and validates clean end-to-end through the C
    validator: the RSA signature verifies, the selected ROOT key (slot 0) is not
    in the revoke set (slots 1,2), and the security version is a bit-superset of
    the host default (all-zero)."""
    from tt_boot_manifest.oca import constants as oca_consts

    bin_path = _pack_config(
        "configs/oca_secure_boot_device_state_example.yaml",
        "secure_boot_device_state_example",
    )
    with open(bin_path, "rb") as f:
        body = f.read()

    # The device-state fields the example demonstrates land in the manifest.
    assert body[oca_consts.OFF_MANIFEST_SECURITY_CONTROL] == 0x00
    msv = body[oca_consts.OFF_MANIFEST_SECURITY_VERSION:
               oca_consts.OFF_MANIFEST_SECURITY_VERSION + 16]
    assert int.from_bytes(msv, "little") == 0x07
    sel = body[oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC:
               oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC + 16]
    assert int.from_bytes(sel, "little") == 0x01
    rev = body[oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE:
               oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE + 16]
    assert int.from_bytes(rev, "little") == 0x06

    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key"])
    assert result.returncode == 0, (
        f"expected PASS; got exit {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    assert PASS_RE.match(result.stdout), (
        f"stdout does not match PASS regex: {result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# Build-time variant gate: [variants] in the build configuration
# ---------------------------------------------------------------------------


def test_gate_classic_only_rejects_pqc():
    """A Classic-only build (PQC compiled out) rejects an OCAP manifest with
    UNSUPPORTED_VARIANT (exit 3) but still validates Classic."""
    cli = _gated_cli("classic-only")
    pqc = _pack_fixture("pqc_basic")
    rejected = _run_cli_at(cli, ["--manifest", pqc])
    assert rejected.returncode == 3, (
        f"expected exit 3; got {rejected.returncode}\nstderr: {rejected.stderr!r}")
    assert re.match(rb"^FAIL: UNSUPPORTED_VARIANT: ", rejected.stderr), \
        rejected.stderr
    classic = _pack_fixture("basic")
    accepted = _run_cli_at(cli, ["--manifest", classic])
    assert accepted.returncode == 0, (
        f"classic-only build must still accept Classic; stderr: {accepted.stderr!r}")


def test_gate_pqc_only_rejects_classic():
    """A PQC-only build (Classic compiled out) rejects an OCAC manifest with
    UNSUPPORTED_VARIANT (exit 3) but still validates PQC."""
    cli = _gated_cli("pqc-only")
    classic = _pack_fixture("basic")
    rejected = _run_cli_at(cli, ["--manifest", classic])
    assert rejected.returncode == 3, (
        f"expected exit 3; got {rejected.returncode}\nstderr: {rejected.stderr!r}")
    assert re.match(rb"^FAIL: UNSUPPORTED_VARIANT: ", rejected.stderr), \
        rejected.stderr
    pqc = _pack_fixture("pqc_basic")
    accepted = _run_cli_at(cli, ["--manifest", pqc])
    assert accepted.returncode == 0, (
        f"pqc-only build must still accept PQC; stderr: {accepted.stderr!r}")


def test_gate_classic_only_rejects_an_mldsa_signed_manifest():
    """The variant gate refuses an ML-DSA-87 signed OCAP manifest before any
    signature is checked."""
    cli = _gated_cli("classic-only")
    result = _run_cli_at(cli, ["--manifest", _pack_fixture("pqc_secure_mldsa"),
                               *_read_flags("pqc_secure_mldsa")])
    assert result.returncode == 3, result.stderr
    assert re.match(rb"^FAIL: UNSUPPORTED_VARIANT: ", result.stderr), result.stderr


@pytest.mark.parametrize("fixture", ["pqc_secure_mldsa", "pqc_hybrid_rsa"])
def test_gate_pqc_only_verifies_an_mldsa_signed_manifest(fixture):
    cli = _gated_cli("pqc-only")
    result = _run_cli_at(cli, ["--manifest", _pack_fixture(fixture), *_read_flags(fixture)])
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("fixture", ["basic", "pqc_basic"])
def test_gate_default_build_accepts_both(fixture):
    """The default build supports every variant — both OCAC and OCAP PASS."""
    cli = _gated_cli("both")
    bin_path = _pack_fixture(fixture)
    result = _run_cli_at(cli, ["--manifest", bin_path])
    assert result.returncode == 0, (
        f"default build must accept {fixture}; got exit {result.returncode}\n"
        f"stderr: {result.stderr!r}")


# ---------------------------------------------------------------------------
# Encrypted payload (AES-128-CBC): authenticate ciphertext, decrypt, confirm
# the plaintext chain, emit plaintext
# ---------------------------------------------------------------------------

_PAYLOAD_SECRET = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
_WRONG_SECRET = "11" * 32
_ENC_BODY_SIZE = {"encrypted_aes": 4096, "encrypted_aes_pqc": 36864}


@pytest.mark.parametrize("fixture",
                         ["encrypted_aes", "encrypted_aes_pqc", "encrypted_aes_pqc_mldsa"])
def test_cli_encrypted_payload_roundtrips(fixture, tmp_path):
    """Correct secret → PASS, and the emitted plaintext is the decrypted
    payload (PTOC-prefixed). Covers both variants and both signature classes."""
    bin_path = _pack_fixture(fixture)
    out = tmp_path / "plain.bin"
    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key",
                       "--payload-secret", _PAYLOAD_SECRET,
                       "--payload-out", str(out)])
    assert result.returncode == 0, f"stderr={result.stderr!r}"
    assert PASS_RE.match(result.stdout), result.stdout
    data = out.read_bytes()
    assert data[:4] == b"PTOC" and len(data) > 32, "emitted plaintext is a PTOC payload"


def test_cli_encrypted_missing_secret_reports_no_provisioned_secret():
    """A missing secret is its own diagnosis, not "the callback is unavailable".

    This used to report CALLBACK_UNAVAILABLE, which conflated three different
    problems behind one code: nothing wired, nothing provisioned, and decryption
    that ran and failed. Only the first is an integration mistake; this one means
    the part was never provisioned for this manifest, which may be a perfectly
    valid manifest on a part that was.
    """
    bin_path = _pack_fixture("encrypted_aes")
    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: NO_PROVISIONED_SECRET: ", result.stderr), result.stderr
    # Distinct from the code an unwired callback would produce.
    assert b"CALLBACK_UNAVAILABLE" not in result.stderr


def test_cli_encrypted_wrong_secret_fails():
    bin_path = _pack_fixture("encrypted_aes")
    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key",
                       "--payload-secret", _WRONG_SECRET])
    assert result.returncode == 1
    # A wrong key fails PKCS#7 unpadding (DECRYPT) or, rarely, the plaintext chain.
    assert re.match(rb"^FAIL: (DECRYPT|PAYLOAD_HASH_CHAIN): ", result.stderr), result.stderr


def test_cli_encrypted_secret_and_plaintext_not_leaked(tmp_path):
    """The secret and the decrypted plaintext go to the key input and the
    --payload-out file respectively — never to stdout/stderr."""
    bin_path = _pack_fixture("encrypted_aes")
    out = tmp_path / "plain.bin"
    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key",
                       "--payload-secret", _PAYLOAD_SECRET,
                       "--payload-out", str(out)])
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    assert _PAYLOAD_SECRET.encode() not in combined, "secret leaked to output"
    plaintext = out.read_bytes()
    assert plaintext[:32] not in combined, "plaintext leaked to output"


def test_cli_encrypted_tampered_ciphertext_fails_before_decrypt(tmp_path):
    src = _pack_fixture("encrypted_aes")
    tampered = tmp_path / "tampered.bin"
    data = bytearray(open(src, "rb").read())
    data[_ENC_BODY_SIZE["encrypted_aes"] + 16] ^= 0xFF  # flip a ciphertext byte
    tampered.write_bytes(bytes(data))
    result = _run_cli(["--manifest", str(tampered), "--trust-any-root-key",
                       "--payload-secret", _PAYLOAD_SECRET])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_HASH: ", result.stderr), result.stderr


# ---------------------------------------------------------------------------
# Cleartext payload validation
#
# A cleartext payload earns the same scrutiny as an encrypted one: payload_hash,
# payload_hash_chain, TOC structural validation, and the per-entry hash check.
# These tests drive each of those against real packer output and real SHA-256.
#
# The helpers below re-seal a tampered bundle: after mutating the payload they
# recompute payload_hash, payload_hash_chain, and manifest_hash so that every
# check EXCEPT the one under test still passes. That isolation is the point —
# without it a single flipped byte trips the first hash and proves nothing about
# the later stages. Re-sealing only works on an unsigned (secure_boot: 0)
# Classic bundle, which is what the `basic` and `multi_image` fixtures are.
# ---------------------------------------------------------------------------


def _toc_image_count(payload: bytes) -> int:
    from tt_boot_manifest.oca import constants as oca_consts
    return int.from_bytes(
        payload[oca_consts.OFF_TOC_IMAGE_COUNT:oca_consts.OFF_TOC_IMAGE_COUNT + 8],
        "little")


def _entry_base(index: int) -> int:
    """Payload-relative byte offset of TOC entry `index`."""
    from tt_boot_manifest.oca import constants as oca_consts
    return oca_consts.TOC_HEADER_SIZE + index * oca_consts.TOC_ENTRY_SIZE


def _entry_u64(payload: bytes, index: int, field_offset: int) -> int:
    base = _entry_base(index) + field_offset
    return int.from_bytes(payload[base:base + 8], "little")


def _set_entry_u64(data: bytearray, index: int, field_offset: int, value: int) -> None:
    from tt_boot_manifest.oca import constants as oca_consts
    base = oca_consts.OCA_CLASSIC_BODY_SIZE + _entry_base(index) + field_offset
    data[base:base + 8] = value.to_bytes(8, "little")


def _reseal_cleartext_bundle(data: bytearray) -> None:
    """Recompute payload_hash, payload_hash_chain, and manifest_hash in place for
    an unsigned cleartext Classic bundle, so only a deliberate defect remains."""
    import hashlib

    from tt_boot_manifest.oca import constants as oca_consts

    body = oca_consts.OCA_CLASSIC_BODY_SIZE
    digest_size = oca_consts.MANIFEST_HASH_DIGEST_SIZE
    payload = bytes(data[body:])

    hashed_len = int.from_bytes(
        data[oca_consts.OFF_PAYLOAD_HASHED_LENGTH:
             oca_consts.OFF_PAYLOAD_HASHED_LENGTH + 8], "little")

    # payload_hash covers the TOC region (payload_hashed_length bytes).
    ph = hashlib.sha256(payload[:hashed_len]).digest()
    data[oca_consts.OFF_PAYLOAD_HASH:oca_consts.OFF_PAYLOAD_HASH + digest_size] = ph

    # payload_hash_chain: H(TOC), then fold in H(image bytes) per stored entry.
    chain = hashlib.sha256(payload[:hashed_len]).digest()
    for i in range(_toc_image_count(payload)):
        off = _entry_u64(payload, i, oca_consts.OFF_TOC_ENTRY_OFFSET)
        ln = _entry_u64(payload, i, oca_consts.OFF_TOC_ENTRY_LENGTH)
        chain = hashlib.sha256(
            chain + hashlib.sha256(payload[off:off + ln]).digest()).digest()
    data[oca_consts.OFF_PAYLOAD_HASH_CHAIN:
         oca_consts.OFF_PAYLOAD_HASH_CHAIN + digest_size] = chain

    # manifest_hash over the signed region (no signature: secure_boot is 0).
    mh = hashlib.sha256(bytes(data[:oca_consts.OCA_CLASSIC_SIGNED_REGION_END])).digest()
    data[oca_consts.OFF_MANIFEST_HASH:oca_consts.OFF_MANIFEST_HASH + digest_size] = mh


def _tampered_bundle(tmp_path, fixture: str, name: str, mutate, reseal: bool = True) -> str:
    """Pack `fixture`, apply `mutate(bytearray)`, optionally re-seal, and write
    the result to tmp_path/name.bin. Returns the path."""
    data = bytearray(open(_pack_fixture(fixture), "rb").read())
    mutate(data)
    if reseal:
        _reseal_cleartext_bundle(data)
    out = tmp_path / f"{name}.bin"
    out.write_bytes(bytes(data))
    return str(out)


# Mutators for _tampered_bundle. Each takes the buffer it edits, so a case that
# needs a parameter binds it with functools.partial rather than closing over it.


def _flip_image_byte(data):
    payload = bytes(data[oca_constants.OCA_CLASSIC_BODY_SIZE:])
    off = _entry_u64(payload, 0, oca_constants.OFF_TOC_ENTRY_OFFSET)
    data[oca_constants.OCA_CLASSIC_BODY_SIZE + off] ^= 0xFF


def _corrupt_entry_hash(data, index):
    pos = (oca_constants.OCA_CLASSIC_BODY_SIZE + _entry_base(index)
           + oca_constants.OFF_TOC_ENTRY_HASH)
    data[pos] ^= 0xFF


def _flip_entry_description(data):
    """The description sits inside the TOC region payload_hash covers."""
    pos = (oca_constants.OCA_CLASSIC_BODY_SIZE + _entry_base(0)
           + oca_constants.OFF_TOC_ENTRY_DESCRIPTION)
    data[pos] ^= 0xFF


def _apply_toc_violation(data, violation):
    payload = bytes(data[oca_constants.OCA_CLASSIC_BODY_SIZE:])
    entry0_off = _entry_u64(payload, 0, oca_constants.OFF_TOC_ENTRY_OFFSET)
    if violation == "misaligned_offset":
        _set_entry_u64(data, 0, oca_constants.OFF_TOC_ENTRY_OFFSET, entry0_off + 1)
    elif violation == "out_of_bounds_length":
        _set_entry_u64(data, 0, oca_constants.OFF_TOC_ENTRY_LENGTH, len(payload))
    elif violation == "zero_length":
        # Re-sealing gives the empty image a correct hash and chain, so
        # nothing but the structural rule can reject it.
        _set_entry_u64(data, 0, oca_constants.OFF_TOC_ENTRY_LENGTH, 0)
    else:
        # Point entry 1 at entry 0's offset so their ranges coincide.
        _set_entry_u64(data, 1, oca_constants.OFF_TOC_ENTRY_OFFSET, entry0_off)


def _inflate_hashed_length(data):
    pos = oca_constants.OFF_PAYLOAD_HASHED_LENGTH
    current = int.from_bytes(data[pos:pos + 8], "little")
    data[pos:pos + 8] = (current + 8).to_bytes(8, "little")


def _shrink_toc_payload_length(data):
    pos = oca_constants.OCA_CLASSIC_BODY_SIZE + oca_constants.OFF_TOC_PAYLOAD_LENGTH
    current = int.from_bytes(data[pos:pos + 8], "little")
    data[pos:pos + 8] = (current - 8).to_bytes(8, "little")


def test_cli_cleartext_payload_is_actually_checked(tmp_path):
    """Flipping a byte inside an image — with no re-seal — must fail. Proves the
    cleartext payload is validated at all, rather than skipped."""
    path = _tampered_bundle(tmp_path, "basic", "image_flip", _flip_image_byte,
                            reseal=False)
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_HASH_CHAIN: ", result.stderr), result.stderr


@pytest.mark.parametrize("index", [0, 1, 2])
def test_cli_cleartext_wrong_entry_hash_rejected(tmp_path, index):
    """A bundle that is self-consistent in every other respect — correct
    payload_hash, correct payload_hash_chain, correct manifest_hash, valid TOC
    structure — but whose TOC entry `hash` does not describe its image bytes must
    be rejected. The chain hashes the stored `hash` field as ordinary TOC data,
    so it cannot catch this; only the per-entry check can. Parametrized over
    every entry so the check covers the whole loop, not just the first entry."""
    path = _tampered_bundle(tmp_path, "multi_image", f"bad_entry_hash_{index}",
                            functools.partial(_corrupt_entry_hash, index=index))
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1, (
        f"entry {index} with a wrong hash must be rejected; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}")
    assert re.match(rb"^FAIL: PAYLOAD_ENTRY_HASH: ", result.stderr), result.stderr


def test_cli_cleartext_tampered_toc_region_fails_on_payload_hash(tmp_path):
    """payload_hash covers the TOC region, and is checked before anything else
    that reads the TOC — so mutating an entry's description trips it first."""
    path = _tampered_bundle(tmp_path, "multi_image", "toc_flip",
                            _flip_entry_description, reseal=False)
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_HASH: ", result.stderr), result.stderr


@pytest.mark.parametrize(
    "violation",
    ["misaligned_offset", "out_of_bounds_length", "overlapping_entries", "zero_length"],
)
def test_cli_cleartext_toc_structural_violations_rejected(tmp_path, violation):
    """TOC structural validation now runs on cleartext payloads too, and reports
    the dedicated PAYLOAD_TOC code rather than a hash mismatch. Each mutation is
    derived from the fixture's own entry offsets, so it stays a violation of the
    intended rule even if the fixture's images change size."""
    path = _tampered_bundle(
        tmp_path, "multi_image", violation,
        functools.partial(_apply_toc_violation, violation=violation))
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_TOC: ", result.stderr), result.stderr


def test_cli_cleartext_hashed_length_must_equal_toc_span(tmp_path):
    """payload_hashed_length must be exactly the TOC span for a cleartext
    payload; re-sealing makes payload_hash agree with the inflated value, so only
    the span check can reject it."""
    path = _tampered_bundle(tmp_path, "multi_image", "hashed_len",
                            _inflate_hashed_length)
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_TOC: ", result.stderr), result.stderr


def test_cli_cleartext_toc_payload_length_must_match_manifest(tmp_path):
    """The TOC's own payload_length and the manifest's must agree for a
    cleartext payload."""
    path = _tampered_bundle(tmp_path, "multi_image", "toc_len",
                            _shrink_toc_payload_length)
    result = _run_cli(["--manifest", path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_TOC: ", result.stderr), result.stderr


def test_cli_cleartext_missing_payload_bytes_is_truncated(tmp_path):
    """A manifest that declares a payload whose bytes are absent is TRUNCATED,
    not silently accepted."""
    src = _pack_fixture("multi_image")
    data = bytearray(open(src, "rb").read())
    out = tmp_path / "no_payload.bin"
    out.write_bytes(bytes(data[:-16]))   # drop the tail of the payload
    result = _run_cli(["--manifest", str(out)])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: TRUNCATED: ", result.stderr), result.stderr


def test_cli_cleartext_entry_field_values_survive_roundtrip():
    """The optional Table-6 fields the fixture sets are present at their spec
    offsets in the bytes the validator accepted — the producer emits them and the
    consumer's layout agrees."""
    from tt_boot_manifest.oca import constants as oca_consts

    bin_path = _pack_fixture("multi_image")
    payload = open(bin_path, "rb").read()[oca_consts.OCA_CLASSIC_BODY_SIZE:]
    assert _toc_image_count(payload) == 3

    assert _entry_u64(payload, 0, oca_consts.OFF_TOC_ENTRY_LOAD_ADDR) == 0x8000_0000
    assert _entry_u64(payload, 0, oca_consts.OFF_TOC_ENTRY_ENTRY_POINT) == 0x40
    assert _entry_u64(payload, 0, oca_consts.OFF_TOC_ENTRY_SECURITY_VERSION) == 3
    assert _entry_u64(payload, 0, oca_consts.OFF_TOC_ENTRY_TARGET_CHIPLET_ID) == 0xA1
    assert _entry_u64(payload, 1, oca_consts.OFF_TOC_ENTRY_LOAD_ADDR) == 0x9000_0000
    # Third image sets no placement fields — they stay 0 ("unused").
    assert _entry_u64(payload, 2, oca_consts.OFF_TOC_ENTRY_LOAD_ADDR) == 0
    assert _entry_u64(payload, 2, oca_consts.OFF_TOC_ENTRY_ENTRY_POINT) == 0

    desc_base = _entry_base(0) + oca_consts.OFF_TOC_ENTRY_DESCRIPTION
    desc = payload[desc_base:desc_base + oca_consts.LEN_TOC_ENTRY_DESCRIPTION]
    assert desc.startswith(b"stage-1 bootloader")
    assert desc[-1] == 0x00

    result = _run_cli(["--manifest", bin_path])
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# FAIL paths
# ---------------------------------------------------------------------------


def test_cli_fail_on_tampered_signed_region():
    bin_path = _pack_fixture("basic")
    with open(bin_path, "r+b") as f:
        f.seek(1000)
        f.write(b"\xFF")
    result = _run_cli(["--manifest", bin_path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: MANIFEST_HASH: ", result.stderr), result.stderr


def test_cli_fail_on_tampered_signature():
    bin_path = _pack_fixture("secure_rsa")
    # Flip a byte inside signature_classic, which starts at offset 3172.
    with open(bin_path, "r+b") as f:
        f.seek(3200)
        f.write(b"\xFF")
    result = _run_cli(["--manifest", bin_path, "--trust-any-root-key"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: SIGNATURE: ", result.stderr), result.stderr


def test_cli_fail_on_bad_magic():
    bin_path = _pack_fixture("basic")
    with open(bin_path, "r+b") as f:
        f.seek(0)
        f.write(b"X")
    result = _run_cli(["--manifest", bin_path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: MAGIC: ", result.stderr), result.stderr


def test_cli_fail_on_truncated_file(tmp_path):
    src = _pack_fixture("basic")
    truncated = tmp_path / "truncated.bin"
    with open(src, "rb") as fin:
        data = fin.read(4000)
    truncated.write_bytes(data)
    result = _run_cli(["--manifest", str(truncated)])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: TRUNCATED: ", result.stderr), result.stderr


def test_cli_usage_error_on_missing_manifest_flag():
    result = _run_cli([])
    assert result.returncode == 2
    assert b"usage:" in result.stderr


def test_cli_quiet_suppresses_pass_line():
    bin_path = _pack_fixture("basic")
    result = _run_cli(["--manifest", bin_path, "--quiet"])
    assert result.returncode == 0
    assert result.stdout == b""


def test_cli_validates_in_under_one_second():
    bin_path = _pack_fixture("control_plane")
    flags = _read_flags("control_plane")
    start = time.perf_counter()
    result = _run_cli(["--manifest", bin_path, *flags])
    elapsed = time.perf_counter() - start
    assert result.returncode == 0
    assert elapsed < 1.0, f"CLI took {elapsed:.3f}s; budget is 1.0s"


# ---------------------------------------------------------------------------
# ECDSA signature length recovery
#
# signature_classic is a fixed 512-byte field that the packer right-pads with
# 0x00, so a consumer has to recover the real DER length from the SEQUENCE
# framing. Inferring it by trimming trailing 0x00 bytes is wrong: a DER INTEGER
# may legitimately end in 0x00 — it happens whenever the low byte of `s` is zero,
# for roughly 1 P-256 signature in 256 — and trimming that byte turns a valid
# signature into a spurious FAIL: SIGNATURE, which reads as firmware tampering.
#
# ECDSA signing here is deterministic (RFC 6979), so sweeping the timestamp over
# a fixed range against the committed test key is reproducible, not probabilistic.
# ---------------------------------------------------------------------------

# Sweep width for finding a trailing-zero DER signature. At ~1/256 per timestamp
# this is wide enough to hold several hits against the committed EC test key.
_ECDSA_SWEEP_TIMESTAMPS = range(1764633600, 1764633600 + 512)

# signature_classic begins where the signed region ends (3145 for Classic).
_SIGNATURE_OFFSET = oca_constants.CLASSIC_VARIANT.signed_region_end
_SIGNATURE_FIELD_SIZE = oca_constants.SIGNATURE_CLASSIC_SIZE


def _ecdsa_bundle_for_timestamp(timestamp: int) -> bytes:
    """Pack the secure_ecdsa fixture with `timestamp` substituted, in process.

    DER is selected explicitly. It is not the default encoding — raw is, because
    raw is the only encoding defined for every algorithm — but DER ECDSA is the
    one variable-length value in the format, so it is what the length-recovery
    tests below need.
    """
    cfg = load_config(os.path.join(FIXTURE_DIR, "secure_ecdsa.yaml"))
    cfg["timestamp"] = timestamp
    cfg["signature_encoding"] = 0x01
    return pack_oca_bundle(cfg)


def _der_signature_length(bundle: bytes) -> int:
    """Total encoded length of the DER ECDSA signature in signature_classic.

    Mirrors der_sequence_total_len() in test/openssl_crypto.c: read the SEQUENCE
    tag and its length octet (always short-form for P-256, whose DER is < 128
    bytes). Returns 0 if the field does not open with a SEQUENCE.
    """
    sig = bundle[_SIGNATURE_OFFSET:_SIGNATURE_OFFSET + _SIGNATURE_FIELD_SIZE]
    if len(sig) < 2 or sig[0] != 0x30:
        return 0
    return 2 + sig[1]


def _validate_bundle(bundle: bytes, tmp_path, name: str) -> subprocess.CompletedProcess:
    """Write `bundle` to a temp file and run it through the CLI."""
    path = tmp_path / f"{name}.bin"
    path.write_bytes(bundle)
    return _run_cli(["--manifest", str(path), "--trust-any-root-key"])


@functools.lru_cache(maxsize=1)
def _ecdsa_sweep() -> tuple:
    """Pack the ECDSA fixture once per timestamp in the sweep and classify each
    signature. Returns a tuple of (timestamp, der_len, ends_in_zero).

    Cached, so the sweep runs once per session no matter how many tests below
    consult it.
    """
    observed = []
    for timestamp in _ECDSA_SWEEP_TIMESTAMPS:
        bundle = _ecdsa_bundle_for_timestamp(timestamp)
        der_len = _der_signature_length(bundle)
        ends_in_zero = (
            der_len > 0 and bundle[_SIGNATURE_OFFSET + der_len - 1] == 0x00
        )
        observed.append((timestamp, der_len, ends_in_zero))
    return tuple(observed)


def test_ecdsa_sweep_contains_a_trailing_zero_der_signature():
    """Premise for the regression test below: the committed EC key does produce
    signatures whose DER ends in 0x00 somewhere in the sweep.

    If a key rotation ever makes that untrue, the regression test silently stops
    testing anything — so fail loudly here instead.
    """
    hits = [ts for ts, _der_len, ends_in_zero in _ecdsa_sweep() if ends_in_zero]
    assert hits, (
        "no ECDSA signature in the sweep ends in 0x00 — the trailing-zero "
        "regression case is no longer reachable with this key; widen "
        "_ECDSA_SWEEP_TIMESTAMPS or re-derive it against the current key"
    )


def test_cli_accepts_every_ecdsa_signature_whose_der_ends_in_zero(tmp_path):
    """A valid signature whose DER happens to end in 0x00 must still verify.

    This is the exact case that inferring the length by trimming trailing 0x00
    padding corrupts: the trim eats a real signature byte, and the manifest is
    reported as FAIL: SIGNATURE.
    """
    hits = [ts for ts, _der_len, ends_in_zero in _ecdsa_sweep() if ends_in_zero]
    for timestamp in hits:
        bundle = _ecdsa_bundle_for_timestamp(timestamp)
        result = _validate_bundle(bundle, tmp_path, f"ecdsa_tz_{timestamp}")
        assert result.returncode == 0, (
            f"ECDSA bundle at timestamp={timestamp} has a DER signature ending "
            f"in 0x00 and was rejected; exit {result.returncode}\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )
        assert PASS_RE.match(result.stdout), result.stdout


def test_cli_accepts_ecdsa_signatures_across_der_lengths(tmp_path):
    """One bundle per distinct DER signature length observed in the sweep.

    P-256 DER varies in length as the leading bit of r or s forces an extra
    padding byte, so this covers the real length variation rather than an
    arbitrary sample — catching off-by-one errors in length recovery that the
    trailing-zero case alone would not.
    """
    by_length = {}
    for timestamp, der_len, _ends_in_zero in _ecdsa_sweep():
        by_length.setdefault(der_len, timestamp)
    assert 0 not in by_length, (
        "some signature_classic field did not open with a DER SEQUENCE: "
        f"timestamp={by_length[0]}"
    )
    assert len(by_length) > 1, (
        f"expected P-256 DER to vary in length across the sweep; saw only "
        f"{sorted(by_length)}"
    )
    for der_len, timestamp in sorted(by_length.items()):
        bundle = _ecdsa_bundle_for_timestamp(timestamp)
        result = _validate_bundle(bundle, tmp_path, f"ecdsa_len{der_len}")
        assert result.returncode == 0, (
            f"ECDSA bundle at timestamp={timestamp} (der_len={der_len}) was "
            f"rejected; exit {result.returncode}\n"
            f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
        )


def test_cli_rejects_ecdsa_signature_with_corrupt_der_header(tmp_path):
    """A signature field that does not open with a well-formed DER SEQUENCE is
    rejected, rather than being length-guessed into an accidental verification."""
    bundle = bytearray(_ecdsa_bundle_for_timestamp(_ECDSA_SWEEP_TIMESTAMPS[0]))
    bundle[_SIGNATURE_OFFSET] = 0x31   # SET instead of SEQUENCE
    result = _validate_bundle(bytes(bundle), tmp_path, "ecdsa_bad_der")
    assert result.returncode == 1
    assert re.match(rb"^FAIL: SIGNATURE: ", result.stderr), result.stderr


# ---------------------------------------------------------------------------
# Post-validation TOC access (oca_payload_region / oca_toc_info /
# oca_toc_image_at), exercised through the CLI's --list-images reference walk.
#
# The sibling test test_cli_cleartext_entry_field_values_survive_roundtrip
# asserts the producer writes each Table-6 field at its spec offset. These
# assert the ACCESSOR API reads those same bytes back correctly — so a wrong
# offset in oca_toc_image_at fails here even though the bytes are right.
# ---------------------------------------------------------------------------

_TOC_RE = re.compile(
    r"^toc: v(?P<major>\d+)\.(?P<minor>\d+) "
    r"payload_length=(?P<payload_length>\d+) images=(?P<images>\d+)$"
)

# `type` is %-16s padded and may contain internal spaces, so the fields are
# matched in their printed order rather than split on whitespace.
_IMAGE_RE = re.compile(
    r"^image\[(?P<index>\d+)\]: type=(?P<type>.*?) +"
    r"offset=(?P<offset>0x[0-9a-f]+|0) length=(?P<length>\d+) "
    r"load_addr=(?P<load_addr>0x[0-9a-f]+|0) "
    r"entry_point=(?P<entry_point>0x[0-9a-f]+|0) "
    r"v(?P<version>\d+\.\d+\.\d+) "
    r"security_version=(?P<security_version>\d+) group=(?P<group>\d+)$"
)


def _parse_listing(stdout: bytes) -> tuple:
    """Parse `--list-images` output into (toc_dict, [image_dict, ...])."""
    toc = None
    images = []
    for line in stdout.decode().splitlines():
        toc_match = _TOC_RE.match(line)
        if toc_match:
            toc = toc_match.groupdict()
            continue
        image_match = _IMAGE_RE.match(line)
        if image_match:
            images.append(image_match.groupdict())
    return toc, images


def test_cli_list_images_absent_unless_requested():
    """--list-images is opt-in; existing callers see byte-identical output."""
    bin_path = _pack_fixture("multi_image")
    without = _run_cli(["--manifest", bin_path])
    with_flag = _run_cli(["--manifest", bin_path, "--list-images"])
    assert without.returncode == 0 and with_flag.returncode == 0
    assert b"toc:" not in without.stdout
    assert b"image[" not in without.stdout
    assert with_flag.stdout.startswith(without.stdout)


def test_cli_list_images_round_trips_every_toc_entry_field():
    """Every value multi_image.yaml sets comes back out through the accessors,
    for all three images, including the third's deliberately-unset placement
    fields."""
    bin_path = _pack_fixture("multi_image")
    result = _run_cli(["--manifest", bin_path, "--list-images"])
    assert result.returncode == 0, result.stderr

    toc, images = _parse_listing(result.stdout)
    assert toc is not None, f"no toc line in {result.stdout!r}"
    assert int(toc["images"]) == 3
    assert len(images) == 3, f"expected 3 image lines, got {images}"

    # Values below are the ones declared in
    # validators/oca/test/fixtures/configs/multi_image.yaml.
    expected = [
        {"type": "MULTIMG BLSTAGE1", "load_addr": 0x8000_0000,
         "entry_point": 0x40, "version": "2.1.0", "security_version": 3, "group": 1},
        {"type": "MULTIMG BLSTAGE2", "load_addr": 0x9000_0000,
         "entry_point": 0x200, "version": "2.1.1", "security_version": 1, "group": 1},
        {"type": "MULTIMG BLMEMMAP", "load_addr": 0,
         "entry_point": 0, "version": "0.0.0", "security_version": 0, "group": 1},
    ]
    for index, (got, want) in enumerate(zip(images, expected)):
        assert int(got["index"]) == index
        assert got["type"] == want["type"], f"image[{index}] type"
        assert int(got["load_addr"], 0) == want["load_addr"], f"image[{index}] load_addr"
        assert int(got["entry_point"], 0) == want["entry_point"], f"image[{index}] entry_point"
        assert got["version"] == want["version"], f"image[{index}] version"
        assert int(got["security_version"]) == want["security_version"], f"image[{index}] security_version"
        assert int(got["group"]) == want["group"], f"image[{index}] group"


def test_cli_list_images_offsets_and_lengths_match_the_payload():
    """Each reported offset/length is 8-byte aligned, in range, and matches the
    image the packer actually placed — the property a ROM relies on before it
    copies img.bytes anywhere."""
    bin_path = _pack_fixture("multi_image")
    bundle = open(bin_path, "rb").read()
    payload = bundle[oca_constants.CLASSIC_VARIANT.body_size:]

    result = _run_cli(["--manifest", bin_path, "--list-images"])
    assert result.returncode == 0, result.stderr
    toc, images = _parse_listing(result.stdout)

    assert int(toc["payload_length"]) == len(payload)
    for image in images:
        offset = int(image["offset"], 0)
        length = int(image["length"])
        assert offset % 8 == 0, f"offset {offset:#x} not 8-byte aligned"
        assert offset + length <= len(payload), "image runs past the payload"
        assert length > 0


def test_cli_list_images_for_encrypted_bundle_uses_recovered_plaintext():
    """An encrypted bundle lists its images from the plaintext the decrypt
    callback recovered — oca_payload_region reports the stored region as
    ciphertext, and the caller substitutes the decrypted buffer."""
    bin_path = _pack_fixture("encrypted_aes")
    flags = _read_flags("encrypted_aes")
    result = _run_cli(["--manifest", bin_path, *flags, "--list-images"])
    assert result.returncode == 0, result.stderr

    toc, images = _parse_listing(result.stdout)
    assert toc is not None, f"no toc line in {result.stdout!r}"
    assert len(images) == int(toc["images"]) == 1
    assert images[0]["type"] == "ENCAESXXBLSTAGE1"


def test_cli_list_images_encrypted_without_secret_lists_nothing():
    """With no secret the bundle fails validation outright, so the TOC walk is
    never reached — no image line may be emitted from ciphertext."""
    bin_path = _pack_fixture("encrypted_aes")
    result = _run_cli(["--manifest", bin_path, "--list-images"])
    assert result.returncode == 1
    assert b"image[" not in result.stdout
    assert b"toc:" not in result.stdout


# ---------------------------------------------------------------------------
# In-place payload decryption
#
# A memory-constrained consumer decrypts over the ciphertext instead of into a
# second full-size buffer. These assert the two modes are indistinguishable in
# result, so the memory saving costs nothing in correctness.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["encrypted_aes", "encrypted_aes_pqc"])
def test_cli_decrypt_in_place_recovers_identical_plaintext(fixture, tmp_path):
    """In-place and copy-out decryption recover byte-identical plaintext."""
    bin_path = _pack_fixture(fixture)
    flags = _read_flags(fixture)

    copy_out = tmp_path / "copy_out.bin"
    in_place = tmp_path / "in_place.bin"
    first = _run_cli(["--manifest", bin_path, *flags, "--payload-out", str(copy_out)])
    second = _run_cli(["--manifest", bin_path, *flags, "--decrypt-in-place",
                       "--payload-out", str(in_place)])

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout, "verdict line differs between modes"
    assert copy_out.read_bytes() == in_place.read_bytes()
    assert len(in_place.read_bytes()) > 0


@pytest.mark.parametrize("fixture", ["encrypted_aes", "encrypted_aes_pqc"])
def test_cli_decrypt_in_place_lists_identical_images(fixture):
    """The TOC walk sees the same images either way — the accessors work on a
    plaintext that overwrote its own ciphertext."""
    bin_path = _pack_fixture(fixture)
    flags = _read_flags(fixture)
    copy_out = _run_cli(["--manifest", bin_path, *flags, "--list-images"])
    in_place = _run_cli(["--manifest", bin_path, *flags, "--decrypt-in-place",
                         "--list-images"])
    assert copy_out.returncode == 0 and in_place.returncode == 0
    assert copy_out.stdout == in_place.stdout
    _toc, images = _parse_listing(in_place.stdout)
    assert len(images) >= 1


def test_cli_decrypt_in_place_consumes_the_ciphertext(tmp_path):
    """In-place decryption really overwrites the stored ciphertext rather than
    quietly copying: the recovered plaintext must differ from the bundle's stored
    payload bytes, and must start with the PTOC magic."""
    bin_path = _pack_fixture("encrypted_aes")
    flags = _read_flags("encrypted_aes")
    stored_payload = open(bin_path, "rb").read()[oca_constants.CLASSIC_VARIANT.body_size:]

    out = tmp_path / "pt.bin"
    result = _run_cli(["--manifest", bin_path, *flags, "--decrypt-in-place",
                       "--payload-out", str(out)])
    assert result.returncode == 0, result.stderr

    plaintext = out.read_bytes()
    assert plaintext[:4] == b"PTOC"
    assert plaintext != stored_payload[:len(plaintext)], "payload was not encrypted?"


def test_cli_decrypt_in_place_is_inert_for_cleartext_bundles():
    """The flag only affects the encrypted path; a cleartext bundle is unchanged."""
    bin_path = _pack_fixture("multi_image")
    without = _run_cli(["--manifest", bin_path, "--list-images"])
    with_flag = _run_cli(["--manifest", bin_path, "--decrypt-in-place", "--list-images"])
    assert without.returncode == 0 and with_flag.returncode == 0
    assert without.stdout == with_flag.stdout


# ---------------------------------------------------------------------------
# image_count cap (OCA_TOC_MAX_IMAGES, [limits] toc_max_images)
#
# The format puts no upper bound on image_count, so the only structural limit is
# that the TOC fit inside the payload -- which grows with the input, while the
# TOC's pairwise overlap check is O(image_count^2). An 8 MiB payload admits 30393
# entries and 4.6e8 comparisons.
#
# The reachability is the point. With secure boot off, manifest_hash and
# payload_hash are unkeyed SHA-256, so anyone able to write flash can satisfy
# every check that precedes the overlap scan. These tests build exactly that
# bundle and assert the validator refuses it on the count instead of grinding
# through the scan.
# ---------------------------------------------------------------------------

# Taken from the packer constants rather than re-literalized. These sit outside
# the C-to-Python layout-sync gate, so a hardcoded offset here would not fail
# that gate when the layout moves — it would quietly corrupt a different field
# and the test would pass or fail for the wrong reason.
_TOC_HEADER_SIZE = oca_constants.TOC_HEADER_SIZE
_TOC_ENTRY_SIZE = oca_constants.TOC_ENTRY_SIZE
_OFF_PAYLOAD_HASH = oca_constants.OFF_PAYLOAD_HASH
_OFF_PAYLOAD_HASHED_LENGTH = oca_constants.OFF_PAYLOAD_HASHED_LENGTH
_OFF_PAYLOAD_LENGTH = oca_constants.OFF_PAYLOAD_LENGTH


def _craft_oversized_toc_bundle(template_path: str, image_count: int, out_path):
    """Build a secure_boot=0 bundle whose TOC declares `image_count` images.

    Every check ahead of the overlap scan is made to pass -- manifest_hash,
    payload_hash, payload_hashed_length, and the TOC's own payload_length -- so a
    validator without a cap runs the full O(n^2) scan. Each entry describes a
    distinct 8-byte image packed end to end after the TOC, so no per-entry rule
    rejects the bundle before the scan is reached.
    """
    import hashlib
    import struct

    body_size = oca_constants.CLASSIC_VARIANT.body_size
    signed_end = oca_constants.CLASSIC_VARIANT.signed_region_end
    manifest_hash_off = signed_end + oca_constants.SIGNATURE_CLASSIC_SIZE

    body = bytearray(open(template_path, "rb").read()[:body_size])
    toc_bytes = _TOC_HEADER_SIZE + image_count * _TOC_ENTRY_SIZE

    # An 8-byte image keeps every offset in the run 8-byte aligned. TOC_ENTRY_SIZE
    # is not a multiple of 8, though, so the TOC itself only ends on the boundary
    # for an even image_count -- pad up to it before the first image.
    image_len = 8
    images_off = (toc_bytes + 7) & ~7
    payload_len = images_off + image_count * image_len

    payload = bytearray(payload_len)
    payload[0:4] = oca_constants.PTOC_MAGIC
    struct.pack_into("<H", payload, oca_constants.OFF_TOC_VERSION_MAJOR, 1)
    struct.pack_into("<Q", payload, oca_constants.OFF_TOC_PAYLOAD_LENGTH, payload_len)
    struct.pack_into("<Q", payload, oca_constants.OFF_TOC_IMAGE_COUNT, image_count)
    for index in range(image_count):
        entry = _TOC_HEADER_SIZE + index * _TOC_ENTRY_SIZE
        struct.pack_into("<Q", payload, entry + oca_constants.OFF_TOC_ENTRY_OFFSET,
                         images_off + index * image_len)
        struct.pack_into("<Q", payload, entry + oca_constants.OFF_TOC_ENTRY_LENGTH,
                         image_len)

    struct.pack_into("<Q", body, _OFF_PAYLOAD_LENGTH, payload_len)
    # payload_hash covers the TOC region alone, which is exactly what
    # payload_hashed_length has to record; the image bytes after it are outside
    # that digest.
    struct.pack_into("<Q", body, _OFF_PAYLOAD_HASHED_LENGTH, toc_bytes)
    digest = hashlib.sha256(bytes(payload[:toc_bytes])).digest()
    body[_OFF_PAYLOAD_HASH:_OFF_PAYLOAD_HASH + 64] = digest + b"\x00" * 32
    manifest_hash = hashlib.sha256(bytes(body[:signed_end])).digest()
    body[manifest_hash_off:manifest_hash_off + 64] = manifest_hash + b"\x00" * 32

    out_path.write_bytes(bytes(body) + bytes(payload))
    return out_path


def _default_toc_max_images() -> int:
    """toc_max_images from the default build configuration, which the CLI is built with."""
    with open(os.path.join(VALIDATOR_DIR, "lib", "oca_config.toml"), "rb") as handle:
        return tomllib.load(handle)["limits"]["toc_max_images"]


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _build_config_text(toc_max_images=256, rsa=True, ecdsa=True, ml_dsa=True,
                       der_rsa=True, der_ecdsa=True, aes_128=True, aes_256=True,
                       encryption=True) -> str:
    """A complete build configuration: the default, with the given changes."""
    return (
        "[variants]\nclassic = true\npqc = true\n"
        f"[limits]\ntoc_max_images = {toc_max_images}\n"
        "[hardening]\nrecheck_security_version = true\n"
        f"[signature_classic]\nrsa_3072_pkcs1v15_sha256 = {_toml_bool(rsa)}\n"
        f"ecdsa_p256_sha256 = {_toml_bool(ecdsa)}\n"
        f"[signature_pqc]\nml_dsa_87 = {_toml_bool(ml_dsa)}\n"
        f"[der]\nrsa_public_key = {_toml_bool(der_rsa)}\n"
        f"ecdsa_signature = {_toml_bool(der_ecdsa)}\n"
        f"[encryption_cipher]\naes_128_cbc = {_toml_bool(encryption and aes_128)}\n"
        f"aes_256_cbc = {_toml_bool(encryption and aes_256)}\n"
        f"[encryption_kdf]\nsp800_108_hmac_sha256 = {_toml_bool(encryption)}\n"
        f"[encryption_key_source]\npreshared = {_toml_bool(encryption)}\n"
    )


def _configured_cli(build_dir, config_text: str) -> str:
    """Build the CLI from a build configuration of its own; return its path."""
    config = os.path.join(build_dir, "build_config.toml")
    os.makedirs(build_dir, exist_ok=True)
    with open(config, "w") as handle:
        handle.write(config_text)
    result = subprocess.run(
        ["make", "-C", VALIDATOR_DIR, f"BUILD={build_dir}", f"CONFIG={config}", "test"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env={**os.environ, "PYTHON": sys.executable},
    )
    if result.returncode != 0:
        pytest.fail(f"configured build failed:\nstdout:\n{result.stdout}\n"
                    f"stderr:\n{result.stderr}")
    return os.path.join(build_dir, "test", "oca-validate")


def _assert_toc_cap_is(cli: str, cap: int, tmp_path) -> None:
    """One image over the cap is refused on the count; exactly at it is not.

    At the cap the bundle fails later, on the hash chain, which is exactly the
    proof that the count check let it through.
    """
    template = _pack_fixture("basic")
    over = _craft_oversized_toc_bundle(template, cap + 1, tmp_path / "over.bin")
    result = _run_cli_at(cli, ["--manifest", str(over)])
    assert re.match(rb"^FAIL: PAYLOAD_TOO_MANY_IMAGES: ", result.stderr), result.stderr

    at_cap = _craft_oversized_toc_bundle(template, cap, tmp_path / "at_cap.bin")
    result = _run_cli_at(cli, ["--manifest", str(at_cap)])
    assert re.match(rb"^FAIL: PAYLOAD_HASH_CHAIN: ", result.stderr), (
        f"a TOC exactly at the cap should pass the count check and fail later; "
        f"got {result.stderr!r}"
    )


def test_oversized_toc_is_rejected_on_the_count(tmp_path):
    """A TOC declaring far more images than the cap is refused on the count.

    PAYLOAD_TOO_MANY_IMAGES rather than PAYLOAD_TOC is the assertion that
    matters: it proves the bail happened in read_toc_span, before the quadratic
    overlap scan, and not as a side effect of some other structural rule.
    """
    bundle = _craft_oversized_toc_bundle(
        _pack_fixture("basic"), 30393, tmp_path / "oversized.bin")
    assert bundle.stat().st_size > 8 * 1024 * 1024, "expected an ~8 MiB bundle"

    start = time.perf_counter()
    result = _run_cli(["--manifest", str(bundle)])
    elapsed = time.perf_counter() - start

    assert result.returncode == 1, result.stderr
    assert re.match(rb"^FAIL: PAYLOAD_TOO_MANY_IMAGES: ", result.stderr), (
        f"expected a count rejection; got {result.stderr!r}"
    )
    # Generous: the uncapped scan measured ~0.4s here, so a regression that
    # reintroduced it would blow well past this even on a slow machine.
    assert elapsed < 5.0, f"took {elapsed:.2f}s — did the cap stop applying?"


def test_toc_just_over_the_cap_is_rejected_and_just_under_is_not(tmp_path):
    """Boundary check against the default configuration's own value, so the test
    tracks the cap rather than hardcoding it."""
    _assert_toc_cap_is(CLI_PATH, _default_toc_max_images(), tmp_path)


def test_the_toc_cap_follows_the_build_configuration(tmp_path):
    """A cap set in the configuration file reaches the built validator."""
    cli = _configured_cli(str(tmp_path / "build"), _build_config_text(toc_max_images=3))
    _assert_toc_cap_is(cli, 3, tmp_path)


# ---------------------------------------------------------------------------
# The algorithm portfolio: what a build configuration turns off is refused
#
# Two CLIs built from reduced configurations. Everything they leave on still
# verifies; everything they turn off is refused as not enabled, before any
# signature is checked.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ecdsa_raw_only_cli(tmp_path_factory):
    """ECDSA P-256 with raw signatures only: no RSA, no ML-DSA, no DER."""
    return _configured_cli(str(tmp_path_factory.mktemp("ecdsa-raw-only")),
                           _build_config_text(rsa=False, ml_dsa=False,
                                              der_rsa=False, der_ecdsa=False))


@pytest.fixture(scope="module")
def rsa_raw_only_cli(tmp_path_factory):
    """RSA-3072 with raw public keys only, and AES-256-CBC only: no ECDSA, no
    ML-DSA, no DER, no AES-128-CBC."""
    return _configured_cli(str(tmp_path_factory.mktemp("rsa-raw-only")),
                           _build_config_text(ecdsa=False, ml_dsa=False,
                                              der_rsa=False, der_ecdsa=False,
                                              aes_128=False))


@pytest.fixture(scope="module")
def no_encryption_cli(tmp_path_factory):
    """The default signature algorithms, with payload encryption turned off."""
    return _configured_cli(str(tmp_path_factory.mktemp("no-encryption")),
                           _build_config_text(encryption=False))


@pytest.mark.parametrize("cli_fixture, fixture, outcome", [
    ("ecdsa_raw_only_cli", "secure_ecdsa", "PASS"),
    ("ecdsa_raw_only_cli", "secure_rsa", "ALGORITHM_NOT_ENABLED"),
    ("ecdsa_raw_only_cli", "pqc_secure_mldsa", "ALGORITHM_NOT_ENABLED"),
    ("ecdsa_raw_only_cli", "pqc_hybrid_ecdsa", "ALGORITHM_NOT_ENABLED"),
    ("rsa_raw_only_cli", "secure_rsa", "PASS"),
    ("rsa_raw_only_cli", "pqc_secure_rsa", "PASS"),
    ("rsa_raw_only_cli", "secure_rsa_der", "ALGORITHM_NOT_ENABLED"),
    ("rsa_raw_only_cli", "secure_ecdsa", "ALGORITHM_NOT_ENABLED"),
    ("rsa_raw_only_cli", "pqc_hybrid_rsa", "ALGORITHM_NOT_ENABLED"),
    ("rsa_raw_only_cli", "encrypted_aes", "PASS"),
    ("rsa_raw_only_cli", "encrypted_aes_pqc", "ALGORITHM_NOT_ENABLED"),
    ("no_encryption_cli", "secure_rsa", "PASS"),
    ("no_encryption_cli", "encrypted_aes", "ALGORITHM_NOT_ENABLED"),
    ("no_encryption_cli", "encrypted_aes_pqc_mldsa", "ALGORITHM_NOT_ENABLED"),
])
def test_a_build_refuses_what_its_configuration_turns_off(request, cli_fixture,
                                                          fixture, outcome):
    cli = request.getfixturevalue(cli_fixture)
    result = _run_cli_at(cli, ["--manifest", _pack_fixture(fixture), *_read_flags(fixture)])
    if outcome == "PASS":
        _assert_passed(result)
    else:
        _assert_refused(result, outcome)


def test_a_der_ecdsa_signature_is_refused_where_der_is_turned_off(tmp_path,
                                                                ecdsa_raw_only_cli):
    """The same DER-signed manifest verifies on the default build."""
    bundle = tmp_path / "der_ecdsa.bin"
    bundle.write_bytes(_ecdsa_bundle_for_timestamp(0))
    args = ["--manifest", str(bundle), "--trust-any-root-key"]
    _assert_passed(_run_cli(args))
    _assert_refused(_run_cli_at(ecdsa_raw_only_cli, args), "ALGORITHM_NOT_ENABLED")


def test_real_multi_image_fixture_is_unaffected_by_the_cap():
    """The cap must not disturb a realistic payload."""
    bin_path = _pack_fixture("multi_image")
    result = _run_cli(["--manifest", bin_path, "--list-images"])
    assert result.returncode == 0, result.stderr
    toc, images = _parse_listing(result.stdout)
    assert int(toc["images"]) == 3
    assert 3 < _default_toc_max_images()


# ---------------------------------------------------------------------------
# Resolving payload_offset in storage
#
# The payload is located through the manifest's payload_offset, not at
# `body + body_size`. Any bundle whose payload does not immediately follow the
# manifest -- which oca-combined produces routinely -- is readable only that way,
# and the spec requires resolving payload_offset and validating the range against
# the trusted boot region.
#
# `--manifest-addr` puts the CLI into storage-image mode: authenticate the
# manifest, resolve payload_offset against the permitted region, copy the payload
# from there, verify it. These tests exercise that flow against bundles a
# contiguous assumption cannot read.
# ---------------------------------------------------------------------------

_COMBINED_BANK_CONFIG = "validators/oca/test/fixtures/configs/basic.yaml"
_ENCRYPTED_BANK_CONFIG = "validators/oca/test/fixtures/configs/encrypted_aes.yaml"


def _pack_combined(tmp_path, name, manifest_offset, payload_offset,
                   config=_COMBINED_BANK_CONFIG):
    """Build a one-bank oca-combined image with the given placement."""
    cfg = tmp_path / f"{name}.yaml"
    cfg.write_text(
        "manifest_format: oca-combined\n"
        f'name: "{name}"\n'
        "combos:\n"
        "  - name: primary\n"
        f"    config: {config}\n"
        f"    manifest_offset: {manifest_offset}\n"
        f"    payload_offset: {payload_offset}\n"
    )
    out = tmp_path / f"{name}.bin"
    result = subprocess.run(
        [sys.executable, "-m", "tt_boot_manifest.pack_images",
         "--config", str(cfg), "--out", str(out)],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, f"packer failed: {result.stderr}"
    return out


def _read_payload_offset(image_path, manifest_offset):
    """The payload_offset field as the packer reconciled it (signed i64)."""
    import struct

    data = image_path.read_bytes()
    field = manifest_offset + oca_constants.OFF_PAYLOAD_OFFSET
    return struct.unpack_from("<q", data, field)[0]


def test_gapped_bank_fails_contiguous_mode_and_passes_storage_mode(tmp_path):
    """A bank whose payload sits well past the body: refused by the contiguous
    entry point, correct once payload_offset is resolved."""
    image = _pack_combined(tmp_path, "gapped", "0x0", "0x8000")
    assert _read_payload_offset(image, 0) == 0x8000

    # Contiguous mode refuses rather than guessing: it reads payload_offset, sees
    # it disagrees with body_size, and says so. Hashing whatever followed the body
    # instead would report PAYLOAD_HASH -- indistinguishable from tampering, and
    # expensive to diagnose.
    contiguous = _run_cli(["--manifest", str(image)])
    assert contiguous.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_LOCATION: ", contiguous.stderr), contiguous.stderr

    staged = _run_cli(["--manifest", str(image), "--manifest-addr", "0x0"])
    assert staged.returncode == 0, staged.stderr
    assert PASS_RE.match(staged.stdout), staged.stdout


def test_payload_before_manifest_validates(tmp_path):
    """A negative payload_offset is legal — the spec says so explicitly — and the
    resolver handles it."""
    image = _pack_combined(tmp_path, "negoff", "0x8000", "0x0")
    assert _read_payload_offset(image, 0x8000) == -0x8000

    staged = _run_cli(["--manifest", str(image), "--manifest-addr", "0x8000"])
    assert staged.returncode == 0, staged.stderr
    assert PASS_RE.match(staged.stdout), staged.stdout


def test_storage_mode_decrypts_with_the_manifest_at_a_non_zero_address(tmp_path):
    """The shared-secret selector is read from the manifest, not from image[0].

    Both halves of the encryption input have to meet correctly here: the secret
    VALUE is external (--payload-secret), the selector naming it is internal to
    the manifest. In storage mode the manifest sits at --manifest-addr, so
    resolving the selector against the start of the image reads unrelated bytes
    and silently picks no secret.

    It also pins the ordering. The selector is resolved inside the decrypt
    callback, which the library reaches only from the payload stage — after
    oca_check_signature. Nothing but the peek is read off an unauthenticated
    manifest.
    """
    image = _pack_combined(tmp_path, "encstaged", "0x8000", "0x10000",
                           config=_ENCRYPTED_BANK_CONFIG)

    staged = _run_cli(["--manifest", str(image), "--manifest-addr", "0x8000",
                       "--trust-any-root-key",
                       "--payload-secret", _PAYLOAD_SECRET])
    assert staged.returncode == 0, staged.stderr
    assert PASS_RE.match(staged.stdout), staged.stdout

    # The right secret is still required — passing is not an artifact of the
    # decrypt step being skipped.
    wrong = _run_cli(["--manifest", str(image), "--manifest-addr", "0x8000",
                      "--trust-any-root-key",
                      "--payload-secret", _WRONG_SECRET])
    assert wrong.returncode == 1, wrong.stdout


def test_storage_mode_locates_the_payload_where_the_manifest_says(tmp_path):
    """The reported location matches payload_offset, for both signs."""
    for name, manifest_off, payload_off, expect in (
        ("fwd", "0x0", "0x8000", 0x8000),
        ("back", "0x8000", "0x0", 0x0),
    ):
        image = _pack_combined(tmp_path, name, manifest_off, payload_off)
        result = _run_cli(["--manifest", str(image),
                           "--manifest-addr", manifest_off, "--list-images"])
        assert result.returncode == 0, result.stderr
        # Parse the value rather than matching a formatted string: C's "%#llx"
        # prints 0 as "0", not "0x0", because the # flag only prefixes nonzero.
        match = re.search(rb"located: payload at (0x[0-9a-f]+|\d+) span",
                          result.stdout)
        assert match, f"{name}: no 'located:' line in {result.stdout!r}"
        located = int(match.group(1), 0)
        assert located == expect, (
            f"{name}: expected the payload at {expect:#x}, got {located:#x}"
        )


def test_storage_mode_rejects_payload_outside_the_permitted_region(tmp_path):
    """Narrowing the region rejects a locator that points outside it — the
    cross-bank confusion case. The bank is fine; the policy forbids reaching it."""
    image = _pack_combined(tmp_path, "gapped_bounds", "0x0", "0x8000")

    ok = _run_cli(["--manifest", str(image), "--manifest-addr", "0x0"])
    assert ok.returncode == 0, ok.stderr

    # Region stops before the payload at 0x8000.
    bounded = _run_cli(["--manifest", str(image), "--manifest-addr", "0x0",
                        "--region-base", "0x0", "--region-limit", "0x4000"])
    assert bounded.returncode == 1
    assert re.match(rb"^FAIL: PAYLOAD_LOCATION: ", bounded.stderr), bounded.stderr


def test_storage_mode_agrees_with_contiguous_mode_on_ordinary_bundles():
    """Every existing fixture has payload_offset == body_size, so the two modes
    must reach identical verdicts. This is the regression guard on the refactor."""
    for fixture in ("basic", "multi_image", "secure_rsa", "all_constraints"):
        bin_path = _pack_fixture(fixture)
        flags = _read_flags(fixture)
        contiguous = _run_cli(["--manifest", bin_path, *flags])
        staged = _run_cli(["--manifest", bin_path, *flags, "--manifest-addr", "0x0"])
        assert contiguous.returncode == staged.returncode, (
            f"{fixture}: contiguous exit {contiguous.returncode} vs staged "
            f"{staged.returncode}\n{contiguous.stderr!r}\n{staged.stderr!r}"
        )
        assert contiguous.stdout == staged.stdout, f"{fixture}: verdict differs"


def test_validate_manifest_only_needs_no_payload():
    """oca_validate_manifest() is reachable through storage mode: pointing it at a
    bundle truncated to the manifest body still authenticates the manifest, where
    full oca_validate() returns TRUNCATED because the payload is absent."""
    bin_path = _pack_fixture("basic")
    body_only = open(bin_path, "rb").read()[:oca_constants.CLASSIC_VARIANT.body_size]
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
        handle.write(body_only)
        path = handle.name
    try:
        # Contiguous mode wants the payload and cannot find it.
        contiguous = _run_cli(["--manifest", path])
        assert contiguous.returncode == 1
        assert re.match(rb"^FAIL: TRUNCATED: ", contiguous.stderr), contiguous.stderr
        # Storage mode authenticates the manifest, then fails to LOCATE the
        # payload -- a different, more accurate diagnosis.
        staged = _run_cli(["--manifest", path, "--manifest-addr", "0x0"])
        assert staged.returncode != 0
        assert b"PAYLOAD" in staged.stderr, staged.stderr
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# manifest_length self-description
#
# A staged consumer sizes its manifest copy from metadata read out of storage
# before anything is authenticated. oca_check_manifest_length is where the
# copied manifest is required to agree about its own size.
#
# For a SIGNED manifest the signature already covers the field, so the check is
# mostly about an accurate diagnosis. It becomes load-bearing when secure boot is
# off: manifest_hash is then an unkeyed SHA-256, so anyone able to write flash can
# change the length and recompute the hash. Without this check that manifest
# validates cleanly, and a consumer sizing its read from it copies 36864 bytes of
# adjacent flash instead of 4096.
# ---------------------------------------------------------------------------


def _rewrite_manifest_length(bundle: bytes, value: int, rehash: bool) -> bytes:
    """Set manifest_length, optionally repairing the (unkeyed) manifest_hash."""
    import hashlib
    import struct

    data = bytearray(bundle)
    struct.pack_into("<I", data, oca_constants.OFF_MANIFEST_LENGTH, value)
    if rehash:
        end = oca_constants.OCA_CLASSIC_SIGNED_REGION_END
        off = end + oca_constants.SIGNATURE_CLASSIC_SIZE
        data[off:off + 32] = hashlib.sha256(bytes(data[:end])).digest()
    return bytes(data)


def test_mislabelled_manifest_length_is_rejected(tmp_path):
    """A Classic body claiming the PQC body size is refused, with a code that says
    so rather than one that reads as tampering."""
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "badlen.bin"
    path.write_bytes(_rewrite_manifest_length(bundle, 36864, rehash=False))

    result = _run_cli(["--manifest", str(path)])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: MANIFEST_LENGTH: ", result.stderr), result.stderr


def test_mislabelled_length_rejected_even_with_a_repaired_unkeyed_hash(tmp_path):
    """The case the check exists for.

    `basic` is secure_boot=0, so manifest_hash is an unkeyed SHA-256 that anyone
    with flash-write access can recompute. Repair it and every cryptographic check
    in the library passes — only the self-description check stands between a
    consumer and a manifest that lies about its own size.
    """
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "badlen_rehashed.bin"
    path.write_bytes(_rewrite_manifest_length(bundle, 36864, rehash=True))

    result = _run_cli(["--manifest", str(path)])
    assert result.returncode == 1, (
        "a manifest lying about its own size, with a repaired unkeyed hash, was "
        f"accepted: {result.stdout!r}"
    )
    assert re.match(rb"^FAIL: MANIFEST_LENGTH: ", result.stderr), result.stderr


def test_a_pqc_manifest_is_held_to_its_own_length(tmp_path):
    """A PQC body claiming the Classic size is refused just as a Classic body
    claiming the PQC size is: each variant has exactly one valid length."""
    bundle = open(_pack_fixture("pqc_basic"), "rb").read()
    path = tmp_path / "pqc_badlen.bin"
    path.write_bytes(_rewrite_manifest_length(
        bundle, oca_constants.OCA_CLASSIC_BODY_SIZE, rehash=False))

    result = _run_cli(["--manifest", str(path)])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: MANIFEST_LENGTH: ", result.stderr), result.stderr


def test_correct_manifest_length_is_unaffected(tmp_path):
    """Rewriting the field to its correct value and repairing the hash still
    passes — so the test above fails on the LENGTH, not on the rewrite itself."""
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "goodlen.bin"
    path.write_bytes(_rewrite_manifest_length(
        bundle, oca_constants.OCA_CLASSIC_BODY_SIZE, rehash=True))

    result = _run_cli(["--manifest", str(path)])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


# ---------------------------------------------------------------------------
# oca_peek_manifest
#
# Storage mode now begins with a peek, so the CLI's "peek:" line is the
# observable behaviour of oca_peek_manifest(). It must report the body size from
# the MAGIC — never from the manifest's self-declared length, which is untrusted
# at that point.
# ---------------------------------------------------------------------------

_PEEK_RE = re.compile(
    rb"^peek: (?P<variant>\S+) v(?P<major>\d+)\.(?P<minor>\d+) "
    rb"body_size=(?P<body_size>\d+) declared=(?P<declared>\d+) "
    rb'id="(?P<identifier>[^"]*)"$',
    re.MULTILINE,
)


def _peek_line(stdout: bytes) -> dict:
    match = _PEEK_RE.search(stdout)
    assert match, f"no peek line in {stdout!r}"
    return {k: v.decode() for k, v in match.groupdict().items()}


@pytest.mark.parametrize(
    "fixture,variant,body_size",
    [("basic", "OCA-Classic", 4096), ("pqc_basic", "OCA-PQC", 36864)],
)
def test_peek_reports_the_variant_and_body_size(fixture, variant, body_size):
    bin_path = _pack_fixture(fixture)
    result = _run_cli(["--manifest", bin_path, "--manifest-addr", "0x0",
                       "--list-images"])
    assert result.returncode == 0, result.stderr
    peek = _peek_line(result.stdout)
    assert peek["variant"] == variant
    assert int(peek["body_size"]) == body_size
    assert int(peek["declared"]) == body_size


def test_peek_sizes_the_read_from_the_magic_not_the_declared_length(tmp_path):
    """A manifest lying about its own length is still peeked correctly — the
    body size comes from the magic — and is then rejected post-copy by
    oca_check_manifest_length()."""
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "liar.bin"
    path.write_bytes(_rewrite_manifest_length(bundle, 0xDEAD, rehash=True))

    result = _run_cli(["--manifest", str(path), "--manifest-addr", "0x0",
                       "--list-images"])
    peek = _peek_line(result.stdout)
    assert int(peek["body_size"]) == 4096, "body_size must come from the magic"
    assert int(peek["declared"]) == 0xDEAD, "declared_length reported as-is"
    # Peek made no trust decision; the post-copy check is what refuses it.
    assert result.returncode == 1
    assert re.match(rb"^FAIL: MANIFEST_LENGTH: ", result.stderr), result.stderr


def test_peek_rejects_a_head_shorter_than_the_minimum(tmp_path):
    """Fewer than OCA_MANIFEST_PEEK_MIN bytes is TRUNCATED, not a guess."""
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "tiny.bin"
    path.write_bytes(bundle[:8])          # under the 20-byte window

    result = _run_cli(["--manifest", str(path), "--manifest-addr", "0x0"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: TRUNCATED: ", result.stderr), result.stderr


def test_peek_rejects_a_head_that_cannot_hold_the_body(tmp_path):
    """The magic says 4096 but the image stops short: refuse rather than copy
    past the end."""
    bundle = open(_pack_fixture("basic"), "rb").read()
    path = tmp_path / "short_body.bin"
    path.write_bytes(bundle[:2048])       # past the peek window, under body_size

    result = _run_cli(["--manifest", str(path), "--manifest-addr", "0x0"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: TRUNCATED: ", result.stderr), result.stderr


# ---------------------------------------------------------------------------
# CLI hardware-flag matrix
# ---------------------------------------------------------------------------

# control_plane.yaml allows lifecycle_chiplet_states = {TEST_DEV, PROD_END}
# and constrains chiplet_id (so a valid --chiplet-id is still required).
_CONTROL_PLANE_CHIPLET = "DEAD" + "A5" * 30
_LIFECYCLE_TOKENS_PASS = ["TEST_DEV", "PROD_END"]
_LIFECYCLE_TOKENS_FAIL = ["PROD", "RMA_SIP", "RMA_CHIPLET",
                         "PROD_DBG_1", "PROD_DBG_2"]


@pytest.mark.parametrize("token", _LIFECYCLE_TOKENS_PASS)
def test_cli_lifecycle_token_in_set_passes(token):
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", _CONTROL_PLANE_CHIPLET,
        "--lifecycle", token,
        "--version-chiplet", "1.0",
    ])
    assert result.returncode == 0, (
        f"expected PASS for token={token}; stderr={result.stderr!r}")


@pytest.mark.parametrize("token", _LIFECYCLE_TOKENS_FAIL)
def test_cli_lifecycle_token_not_in_set_fails(token):
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", _CONTROL_PLANE_CHIPLET,
        "--lifecycle", token,
        "--version-chiplet", "1.0",
    ])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: LIFECYCLE: ", result.stderr), result.stderr


@pytest.mark.parametrize(
    "major,minor,expect_pass",
    [
        (0, 9,   False),   # below min (manifest min = 1.0, max absent)
        (1, 0,   True),    # at min
        (1, 1,   True),    # above min
        (255, 0, True),    # well above min, no max in manifest
    ],
)
def test_cli_version_range_boundary(major, minor, expect_pass):
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", _CONTROL_PLANE_CHIPLET,
        "--lifecycle", "TEST_DEV",
        "--version-chiplet", f"{major}.{minor}",
    ])
    if expect_pass:
        assert result.returncode == 0, (
            f"expected PASS for {major}.{minor}; stderr={result.stderr!r}")
    else:
        assert result.returncode == 1
        assert re.match(rb"^FAIL: VERSION_RANGE: ", result.stderr), result.stderr


def test_cli_hex_flag_accepts_0x_prefix():
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", "0x" + _CONTROL_PLANE_CHIPLET,
        "--lifecycle", "TEST_DEV",
        "--version-chiplet", "1.0",
    ])
    assert result.returncode == 0, f"stderr={result.stderr!r}"


def test_cli_hex_flag_rejects_non_hex():
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", "ZZ" * 32,
    ])
    assert result.returncode == 2
    assert b"--chiplet-id" in result.stderr


def test_cli_missing_hwid_flag_when_constraint_active():
    """control_plane requires a chiplet_id match — invoking without
    --chiplet-id makes the hardware callback report UNAVAILABLE, and
    the validator should bubble that up as CALLBACK_UNAVAILABLE."""
    bin_path = _pack_fixture("control_plane")
    result = _run_cli([
        "--manifest", bin_path,
        "--lifecycle", "TEST_DEV",
        "--version-chiplet", "1.0",
    ])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: CALLBACK_UNAVAILABLE: ", result.stderr), \
        result.stderr


# ---------------------------------------------------------------------------
# CLI flag-parser edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_version",
    ["1.99999",   # minor exceeds 65535
     "65536.0",   # major exceeds 65535
     "abc.def",   # not numeric
     "1",         # missing dot
     "1.",        # trailing dot, no minor
     "1.2.3"],    # too many components
)
def test_cli_rejects_malformed_version_flag(bad_version):
    bin_path = _pack_fixture("basic")
    result = _run_cli([
        "--manifest", bin_path,
        "--version-chiplet", bad_version,
    ])
    assert result.returncode == 2, (
        f"expected usage error for version={bad_version}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}")
    assert b"--version-chiplet" in result.stderr


def test_cli_rejects_short_hex_flag():
    bin_path = _pack_fixture("basic")
    result = _run_cli([
        "--manifest", bin_path,
        "--chiplet-id", "DEAD",   # only 4 chars, need 64
    ])
    assert result.returncode == 2
    assert b"--chiplet-id" in result.stderr


# ---------------------------------------------------------------------------
# Encryption requires confirmed secure boot
#
# The packer refuses to emit a manifest declaring encryption without secure boot
# — that refusal is itself a requirement — so the negative artifact is built
# here. Two steps are easy to omit, and each produces a refusal that LOOKS like
# a pass while never reaching the check under test:
#
#   * `manifest_hash` must be recomputed. The encryption control bit at offset
#     200 lies inside the signed region and the hash check runs early, so an
#     un-rehashed tamper fails with MANIFEST_HASH.
#   * the base bundle must be CLEARTEXT and non-secure: an encrypted fixture is a
#     secure-boot manifest, which the gate under test lets through.
# ---------------------------------------------------------------------------

_ENCRYPTION_GATE_RE = re.compile(rb"^FAIL: ENCRYPTION_REQUIRES_SECURE_BOOT")


def _pack_encryption_without_secure_boot(tmp_path):
    """A bundle declaring an encrypted payload with secure boot disabled.

    Unbuildable by the packer by design, so it is assembled by tampering a
    cleartext non-secure bundle and re-hashing the signed region.
    """
    import hashlib
    import pathlib

    src = _pack_fixture("basic")
    data = bytearray(pathlib.Path(src).read_bytes())

    data[oca_constants.OFF_PAYLOAD_ENCRYPTION_CONTROL] |= 0x01
    end = oca_constants.OCA_CLASSIC_SIGNED_REGION_END
    digest = hashlib.sha256(bytes(data[:end])).digest()
    off = oca_constants.OFF_MANIFEST_HASH
    data[off:off + 32] = digest

    out = tmp_path / "encrypted_without_secure_boot.bin"
    out.write_bytes(bytes(data))
    return out


def test_cli_refuses_encrypted_payload_without_secure_boot(tmp_path):
    """The whole-bundle entry point refuses with the reason that names the
    policy, not one that merely happens to reject."""
    image = _pack_encryption_without_secure_boot(tmp_path)

    result = _run_cli(["--manifest", str(image)])
    assert result.returncode == 1, result.stdout
    assert _ENCRYPTION_GATE_RE.match(result.stderr), result.stderr
    # If either tamper step were wrong the run would still fail — for the wrong
    # reason — and the test would be worthless.
    assert b"MANIFEST_HASH" not in result.stderr, result.stderr


def test_cli_refusal_does_not_leak_secret_or_derivation_inputs(tmp_path):
    """The diagnostic names the policy, never the material. Checked against the
    whole CLI output rather than the reason line alone, because a debug aid
    added later would land there too."""
    import pathlib

    image = _pack_encryption_without_secure_boot(tmp_path)
    data = pathlib.Path(image).read_bytes()

    result = _run_cli(["--manifest", str(image),
                       "--payload-secret", _PAYLOAD_SECRET])
    assert result.returncode == 1, result.stdout

    combined = result.stdout + result.stderr
    assert bytes.fromhex(_PAYLOAD_SECRET) not in combined
    assert _PAYLOAD_SECRET.encode() not in combined
    assert _PAYLOAD_SECRET.upper().encode() not in combined

    kdf_off = oca_constants.OFF_ENCRYPTION_KDF_INPUT
    kdf_input = data[kdf_off:kdf_off + 64]
    assert kdf_input not in combined
    assert kdf_input.hex().encode() not in combined


def test_staged_flow_refuses_before_locating_the_payload(tmp_path):
    """The staged sequence rejects at the manifest stage, so a boot ROM never
    spends a payload copy on a manifest it was always going to refuse."""
    image = _pack_encryption_without_secure_boot(tmp_path)

    result = _run_cli(["--manifest", str(image), "--manifest-addr", "0x0",
                       "--list-images"])
    assert result.returncode == 1, result.stdout
    assert _ENCRYPTION_GATE_RE.match(result.stderr), result.stderr
    # --list-images prints "located: payload at ..." once the payload has been
    # found and read. Its absence is the evidence that none was touched.
    assert b"located:" not in result.stdout, result.stdout


def test_encrypted_fixtures_still_validate():
    """The shipped encrypted configs carry secure_boot: 1, authenticate, and are
    unaffected — the guard against closing the hole by breaking the feature."""
    for name in ("encrypted_aes", "encrypted_aes_pqc"):
        bin_path = _pack_fixture(name)
        flags = _read_flags(name)
        result = _run_cli(["--manifest", bin_path, *flags])
        assert result.returncode == 0, f"{name}: {result.stderr}"
        assert PASS_RE.match(result.stdout), f"{name}: {result.stdout}"


# ---------------------------------------------------------------------------
# A device reporting secure boot definitively disabled
#
# --secure-boot-disabled models a part settled as non-secure by life-cycle state
# or a discrete disable fuse. It relaxes the requirement the DEVICE imposes, and
# nothing else — the two tests after the first are what keep that claim honest.
# ---------------------------------------------------------------------------


def test_cli_secure_boot_disabled_boots_a_non_secure_image():
    """The feature's purpose: a part settled as non-secure runs a cleartext image
    whose manifest does not assert secure boot."""
    bin_path = _pack_fixture("basic")
    result = _run_cli(["--manifest", bin_path, "--secure-boot-disabled"])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


def test_cli_secure_boot_disabled_does_not_downgrade_a_secure_manifest():
    """The safety property, end to end. `secure_rsa` asserts secure boot in its
    signed region, so the signature is still verified however the device reports
    itself — a corrupted one must still fail, and fail as SIGNATURE rather than
    anything naming the device state. Were the precedence inverted, the disable
    answer would suppress verification and this bundle would pass."""
    bin_path = _pack_fixture("secure_rsa")
    with open(bin_path, "r+b") as f:      # a byte inside signature_classic
        f.seek(3200)
        f.write(b"\xFF")
    result = _run_cli(["--manifest", bin_path, "--secure-boot-disabled",
                       "--trust-any-root-key"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: SIGNATURE: ", result.stderr), result.stderr


def test_cli_secure_boot_disabled_does_not_break_an_encrypted_bundle():
    """An encrypted payload still decrypts on a part reporting itself disabled,
    because encryption requires a manifest that asserts secure boot — and that
    assertion outranks the device, so secure boot stays in force and the
    authentication the encryption gate demands still happens.

    The complementary case, an encrypted payload on a manifest with the bit
    clear, has no CLI expression: the producer refuses to build it
    (`encrypted_payload=1 requires secure_boot=1`). It can only arrive from a
    hand-crafted manifest, which is where the consumer-side refusal is tested."""
    bin_path = _pack_fixture("encrypted_aes")
    flags = _read_flags("encrypted_aes")
    result = _run_cli(["--manifest", bin_path, *flags, "--secure-boot-disabled"])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


# ---------------------------------------------------------------------------
# A device that ENFORCES secure boot
#
# --secure-boot-active is input (3) of the determination, and until it existed
# the CLI could not reach that input at all: it hard-reported false, so every
# end-to-end run was decided by the manifest's own bit or by the fail-safe. The
# device-enforced route — and the per-check confirm that guards it — had no
# expression outside the C unit tests.
# ---------------------------------------------------------------------------


def test_cli_secure_boot_active_engages_verification_on_a_bit_clear_manifest():
    """The device decides, and the decision reaches the checks.

    `basic` does not assert secure boot, so nothing in the manifest names a
    signature class to verify with. With the device reporting enforcement,
    secure boot is in force and that empty class selection is itself the
    rejection — the manifest demands verification it cannot describe. A pass
    here would mean the determination never reached the gated checks."""
    bin_path = _pack_fixture("basic")
    result = _run_cli(["--manifest", bin_path, "--secure-boot-active"])
    assert result.returncode == 1, result.stdout
    assert re.match(rb"^FAIL: SIGNATURE_CLASS_CONTROL: ", result.stderr), \
        result.stderr


def test_cli_secure_boot_active_is_outranked_by_a_device_disable():
    """Input (2) outranks input (3), on the real precedence rather than a stub.

    Both reporters wired and disagreeing: disabled wins, so the same bundle that
    fails above passes here."""
    bin_path = _pack_fixture("basic")
    result = _run_cli([
        "--manifest", bin_path, "--secure-boot-active", "--secure-boot-disabled",
    ])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


def test_cli_secure_boot_active_still_validates_a_properly_signed_bundle():
    """The positive control. Without it the test above passes on a build where
    --secure-boot-active fails everything indiscriminately."""
    bin_path = _pack_fixture("secure_rsa")
    result = _run_cli(["--manifest", bin_path, "--secure-boot-active",
                       "--trust-any-root-key"])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


# secure_boot_control of pqc_secure_mldsa: enforced (bit 0) and the PQC class
# (bit 2). Clearing bit 0 leaves a manifest that names the PQC class but does not
# assert secure boot itself.
_PQC_ONLY_ENFORCED = 0x05
_PQC_ONLY_NOT_ENFORCED = 0x04


def _device_enforced_pqc_bundle() -> bytearray:
    """pqc_secure_mldsa with its enforced bit cleared, re-signed.

    The producer refuses to build this — a signature class requires
    `secure_boot: 1` — so it is tooled here. Only a device that enforces secure
    boot itself uses the PQC class it names."""
    data = _fixture_bytes("pqc_secure_mldsa")
    assert data[oca_constants.OFF_SECURE_BOOT_CONTROL] == _PQC_ONLY_ENFORCED
    data[oca_constants.OFF_SECURE_BOOT_CONTROL] = _PQC_ONLY_NOT_ENFORCED
    _resign_pqc(data, "pqc_secure_mldsa")
    return data


def test_cli_a_device_that_enforces_secure_boot_verifies_the_pqc_class_alone(tmp_path):
    """The device-enforced route on an OCA-PQC manifest: the device puts secure
    boot in force, and the manifest's class bit selects ML-DSA-87, authorized by
    a real anchor."""
    result = _run_bundle(tmp_path, _device_enforced_pqc_bundle(), "device_enforced_pqc",
                         flags=("--secure-boot-active",
                                "--root-key-digest-pqc", _mldsa_dev_key_digest()))
    _assert_passed(result)


@pytest.mark.parametrize("flip_signature,anchor,code", [
    (True, "dev", "SIGNATURE"),
    (False, "other", "ROOT_KEY_UNAUTHORIZED"),
])
def test_cli_the_device_enforced_pqc_route_still_verifies_and_authorizes(
        tmp_path, flip_signature, anchor, code):
    data = _device_enforced_pqc_bundle()
    if flip_signature:
        data[oca_constants.OFF_SIGNATURE_PQC] ^= 0x01
    digest = (_mldsa_dev_key_digest() if anchor == "dev"
              else _key_digest(_fresh_mldsa_key().public_key().public_bytes_raw()))
    result = _run_bundle(tmp_path, data, f"device_enforced_pqc_{code}",
                         flags=("--secure-boot-active", "--root-key-digest-pqc", digest))
    _assert_refused(result, code)


def test_cli_without_the_device_the_pqc_class_bit_alone_verifies_nothing(tmp_path):
    """The contrast that shows the device decides: with the enforced bit clear
    and no device enforcement, secure boot is not in force, so even a broken
    signature boots."""
    data = _device_enforced_pqc_bundle()
    data[oca_constants.OFF_SIGNATURE_PQC] ^= 0x01
    _assert_passed(_run_bundle(tmp_path, data, "pqc_class_bit_only", flags=()))


def test_cli_reports_a_reason_for_every_refusal_it_can_produce(tmp_path):
    """A failure code with no `reason_for` case would print `FAIL: CODE: ok`,
    which reads as a pass to anyone skimming a CI log. The switch has no
    `default:`, so -Wswitch fails the build on an omission; this checks the
    reason actually reaches stderr."""
    bin_path = _pack_encryption_without_secure_boot(tmp_path)
    result = _run_cli(["--manifest", bin_path])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: ENCRYPTION_REQUIRES_SECURE_BOOT: ", result.stderr), \
        result.stderr
    assert not result.stderr.rstrip().endswith(b": ok"), (
        f"no reason text for this code: {result.stderr!r}")


# ---------------------------------------------------------------------------
# Refusals carry their reason
#
# Each case below tampers one signed field and re-seals manifest_hash, so the
# bundle survives the integrity check and is refused by the check under test.
# ---------------------------------------------------------------------------


def _reseal_manifest_hash(data: bytearray) -> None:
    """Recompute manifest_hash over the signed region in place, for either
    variant. Any signature over the region is left stale."""
    import hashlib

    from tt_boot_manifest.oca import constants as oca_consts

    if bytes(data[:4]) == oca_consts.OCAP_MAGIC:
        region_end = oca_consts.PQC_SIGNED_REGION_END
        hash_off = oca_consts.OFF_PQC_MANIFEST_HASH
    else:
        region_end = oca_consts.OCA_CLASSIC_SIGNED_REGION_END
        hash_off = oca_consts.OFF_MANIFEST_HASH
    digest = hashlib.sha256(bytes(data[:region_end])).digest()
    data[hash_off:hash_off + len(digest)] = digest


def _set_le(data: bytearray, offset: int, width: int, value: int) -> None:
    data[offset:offset + width] = value.to_bytes(width, "little")


@pytest.mark.parametrize("code,mutate", [
    # One short of the raw RSA-3072 signature length.
    ("CRYPTO_FIELD_SIZE", functools.partial(
        _set_le, offset=oca_constants.OFF_SIGNATURE_SIZE_CLASSIC, width=2, value=383)),
    # A classical group code that is neither 0x00 nor the 0xCA constant.
    ("GROUP_CODE", functools.partial(
        _set_le, offset=oca_constants.OFF_SIGNATURE_CLASS_REVOKE + 1, width=1, value=0x01)),
])
def test_cli_names_the_reason_for_a_malformed_signing_description(tmp_path, code, mutate):
    """Each refusal prints its own reason after the code, never a bare `ok`."""
    data = bytearray(open(_pack_fixture("secure_rsa"), "rb").read())
    mutate(data)
    _reseal_manifest_hash(data)
    bin_path = tmp_path / f"{code.lower()}.bin"
    bin_path.write_bytes(bytes(data))

    result = _run_cli(["--manifest", str(bin_path), "--trust-any-root-key"])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: " + code.encode() + rb": ", result.stderr), result.stderr
    assert not result.stderr.rstrip().endswith(b": ok"), (
        f"no reason text for this code: {result.stderr!r}")


@pytest.mark.parametrize("byte,classes", [
    (oca_constants.SIGNATURE_CLASS_REVOKE_CLASSIC_CLASSES_SHIFT // 8,
     oca_constants.SIGNATURE_CLASS_REVOKE_CLASSIC_DEFINED_CLASSES),
    (oca_constants.SIGNATURE_CLASS_REVOKE_PQC_CLASSES_SHIFT // 8,
     oca_constants.SIGNATURE_CLASS_REVOKE_PQC_DEFINED_CLASSES),
], ids=["classical", "pqc"])
def test_cli_refuses_a_group_disabled_by_its_class_bits_alone(tmp_path, byte, classes):
    data = _fixture_bytes("secure_rsa")
    data[oca_constants.OFF_SIGNATURE_CLASS_REVOKE + byte] = classes
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, f"class_bits_{byte}"), "GROUP_CODE")


def test_cli_help_documents_every_exit_code():
    """main() exits 3 for a variant this build does not support; --help says so."""
    result = _run_cli(["--help"])
    assert result.returncode == 0
    for code in (b"0 = PASS", b"1 = FAIL", b"2 = usage error",
                 b"3 = manifest variant not supported"):
        assert code in result.stdout, f"--help does not document {code!r}"


# ---------------------------------------------------------------------------
# ROOT-key trust anchor
#
# These drive --root-key-digest, the CLI's stand-in for a key digest held by a
# device: a SHA-256 over the whole key as the manifest encodes it, bound to one
# select slot (slot 0 unless the flag says otherwise). Digests are computed here
# from the committed development keys rather than committed as literals; the
# fixtures whose .flags carry a real anchor are pinned to these below.
# ---------------------------------------------------------------------------

RSA_F4_KEY = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "rsa_private_key.f4.pem")
RSA_E3_KEY = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "rsa_private_key.e3.pem")
EC_P256_KEY = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "ec_private_key.pem")


def _public_key_of(key_path: str):
    from cryptography.hazmat.primitives import serialization

    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None).public_key()


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _rsa_raw_key_digest(key_path: str) -> str:
    """SHA-256 of the key's 388-byte raw encoding — big-endian modulus, then a
    4-byte big-endian exponent — as --root-key-digest takes it."""
    numbers = _public_key_of(key_path).public_numbers()
    return _sha256_hex(numbers.n.to_bytes(384, "big") + numbers.e.to_bytes(4, "big"))


def _rsa_der_key_digest(key_path: str) -> str:
    """SHA-256 of the key's PKCS#1 RSAPublicKey DER encoding."""
    from cryptography.hazmat.primitives import serialization

    return _sha256_hex(_public_key_of(key_path).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1))


def _ec_raw_point_digest(public_key) -> str:
    """SHA-256 of a P-256 key's 65-byte SEC1 uncompressed point."""
    from cryptography.hazmat.primitives import serialization

    return _sha256_hex(public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def _ec_raw_key_digest(key_path: str) -> str:
    return _ec_raw_point_digest(_public_key_of(key_path))


def test_cli_root_key_digest_authorizes_the_matching_key():
    result = _run_cli(["--manifest", _pack_fixture("secure_rsa"),
                       "--root-key-digest", _rsa_raw_key_digest(RSA_F4_KEY)])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


@pytest.mark.parametrize("fixture,anchor_key", [
    ("secure_rsa", RSA_E3_KEY),     # a different RSA-3072 key
    ("secure_ecdsa", RSA_F4_KEY),   # an anchor for a key of another algorithm
])
def test_cli_root_key_digest_refuses_every_other_key(fixture, anchor_key):
    result = _run_cli(["--manifest", _pack_fixture(fixture),
                       "--root-key-digest", _rsa_raw_key_digest(anchor_key)])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: ROOT_KEY_UNAUTHORIZED: ", result.stderr), result.stderr


def test_cli_without_an_anchor_refuses_a_signed_manifest():
    """No anchor flag at all fails closed rather than trusting the embedded key."""
    result = _run_cli(["--manifest", _pack_fixture("secure_rsa")])
    assert result.returncode == 1
    assert re.match(rb"^FAIL: ROOT_KEY_UNAUTHORIZED: ", result.stderr), result.stderr


@pytest.mark.parametrize("digest_first", [True, False])
@pytest.mark.parametrize("bad_digest", ["ab" * 31, "zz" * 32, ""])
def test_cli_rejects_a_malformed_root_key_digest(digest_first, bad_digest):
    """A malformed anchor is a usage error wherever it sits on the command line.
    It must never be dropped while validation goes ahead without it."""
    manifest_args = ["--manifest", _pack_fixture("basic")]
    digest_args = ["--root-key-digest", bad_digest]
    args = digest_args + manifest_args if digest_first else manifest_args + digest_args

    result = _run_cli(args)
    assert result.returncode == 2, (
        f"expected a usage error; rc={result.returncode} stderr={result.stderr!r}")
    assert b"--root-key-digest" in result.stderr


@pytest.mark.parametrize("fixture,digest_of,key_path", [
    ("secure_rsa", _rsa_raw_key_digest, RSA_F4_KEY),
    ("secure_rsa_der", _rsa_der_key_digest, RSA_F4_KEY),
    ("secure_rsa_e3_der", _rsa_der_key_digest, RSA_E3_KEY),
    ("secure_ecdsa", _ec_raw_key_digest, EC_P256_KEY),
], ids=["rsa-raw", "rsa-der", "rsa-e3-der", "ecdsa-raw"])
def test_cli_classical_anchor_authorizes_every_key_shape(fixture, digest_of, key_path):
    """Every classical key the format can carry has an anchor: raw and PKCS#1
    DER RSA-3072, and a raw P-256 point."""
    _assert_passed(_run_cli(["--manifest", _pack_fixture(fixture),
                             "--root-key-digest", digest_of(key_path)]))


def test_cli_classical_anchor_refuses_another_ecdsa_key():
    from cryptography.hazmat.primitives.asymmetric import ec

    other = _ec_raw_point_digest(ec.generate_private_key(ec.SECP256R1()).public_key())
    _assert_refused(_run_cli(["--manifest", _pack_fixture("secure_ecdsa"),
                              "--root-key-digest", other]), "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("fixture,digest_of", [
    ("secure_rsa_der", _rsa_raw_key_digest),
    ("secure_rsa", _rsa_der_key_digest),
], ids=["der-key-raw-anchor", "raw-key-der-anchor"])
def test_cli_an_anchor_binds_the_key_encoding(fixture, digest_of):
    """A digest is over one encoding, so the raw and DER forms of the same RSA
    key are different anchors."""
    _assert_refused(_run_cli(["--manifest", _pack_fixture(fixture),
                              "--root-key-digest", digest_of(RSA_F4_KEY)]),
                    "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("fixture,digest_of,key_path", [
    ("secure_rsa_der", _rsa_der_key_digest, RSA_F4_KEY),
    ("secure_ecdsa", _ec_raw_key_digest, EC_P256_KEY),
], ids=["rsa-der", "ecdsa-raw"])
def test_cli_classical_anchor_covers_the_whole_key(tmp_path, fixture, digest_of, key_path):
    """The last declared byte of the key — the end of the DER exponent, the end
    of the point's Y coordinate — is under the digest too."""
    data = _fixture_bytes(fixture)
    size = struct.unpack_from("<H", data, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    data[oca_constants.OFF_PUBLIC_KEY_CLASSIC + size - 1] ^= 0x02
    _reseal_manifest_hash(data)
    result = _run_bundle(tmp_path, data, f"{fixture}_altered_key",
                         flags=("--root-key-digest", digest_of(key_path)))
    _assert_refused(result, "ROOT_KEY_UNAUTHORIZED")


# ---------------------------------------------------------------------------
# Signing fields on a non-secure manifest are ignored
#
# A Consumer ignores the Secure-Boot-only fields while secure boot is disabled,
# so a non-secure bundle whose signing fields are populated still boots. The
# signatures lie in the unsigned tail; the public keys are signed, so their
# tamper re-seals manifest_hash.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture,offset,reseal", [
    ("basic", oca_constants.OFF_SIGNATURE_CLASSIC, False),
    ("basic", oca_constants.OFF_PUBLIC_KEY_CLASSIC, True),
    ("pqc_basic", oca_constants.OFF_SIGNATURE_PQC, False),
    ("pqc_basic", oca_constants.OFF_PUBLIC_KEY_PQC, True),
    ("pqc_basic", oca_constants.OFF_SIGNATURE_TYPE_PQC, True),
])
def test_cli_non_secure_bundle_with_populated_signing_fields_validates(
        tmp_path, fixture, offset, reseal):
    data = bytearray(open(_pack_fixture(fixture), "rb").read())
    data[offset] ^= 0x5A
    if reseal:
        _reseal_manifest_hash(data)
    bin_path = tmp_path / f"{fixture}_dirty_{offset}.bin"
    bin_path.write_bytes(bytes(data))

    result = _run_cli(["--manifest", str(bin_path)])
    assert result.returncode == 0, result.stderr
    assert PASS_RE.match(result.stdout), result.stdout


# ---------------------------------------------------------------------------
# ML-DSA-87: the PQC signature class end to end
#
# The fixtures sign with the committed ML-DSA-87 development key: PQC-only
# (pqc_secure_mldsa), hybrid with RSA-3072 and with ECDSA P-256, and PQC-only
# with an encrypted payload. The harness verifies pure FIPS 204 ML-DSA-87 over
# the raw signed region with the empty context. Tampering with a signed byte
# re-seals manifest_hash, so the bundle reaches the check under test.
# ---------------------------------------------------------------------------

ML_DSA_87_KEY = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "mldsa87_private_key.pem")
MLDSA_FIXTURES = ["pqc_secure_mldsa", "pqc_hybrid_rsa", "pqc_hybrid_ecdsa"]
HYBRID_FIXTURES = ["pqc_hybrid_rsa", "pqc_hybrid_ecdsa"]

_SIGNATURE_PQC_SPAN = slice(oca_constants.OFF_SIGNATURE_PQC,
                            oca_constants.OFF_SIGNATURE_PQC
                            + oca_constants.ML_DSA_87_SIGNATURE_BYTES)
_PUBLIC_KEY_PQC_SPAN = slice(oca_constants.OFF_PUBLIC_KEY_PQC,
                             oca_constants.OFF_PUBLIC_KEY_PQC
                             + oca_constants.ML_DSA_87_PUBLIC_KEY_BYTES)


def _mldsa_dev_key():
    from cryptography.hazmat.primitives import serialization

    with open(ML_DSA_87_KEY, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _fresh_mldsa_key():
    from cryptography.hazmat.primitives.asymmetric import mldsa

    return mldsa.MLDSA87PrivateKey.generate()


def _key_digest(raw_public_key: bytes) -> str:
    """SHA-256 of a raw public key, as --root-key-digest-pqc takes it."""
    import hashlib

    return hashlib.sha256(raw_public_key).hexdigest()


def _mldsa_dev_key_digest() -> str:
    return _key_digest(_mldsa_dev_key().public_key().public_bytes_raw())


def _fixture_bytes(fixture: str) -> bytearray:
    with open(_pack_fixture(fixture), "rb") as f:
        return bytearray(f.read())


def _run_bundle(tmp_path, data: bytearray, name: str,
                flags=("--trust-any-root-key",)) -> subprocess.CompletedProcess:
    path = tmp_path / f"{name}.bin"
    path.write_bytes(bytes(data))
    return _run_cli(["--manifest", str(path), *flags])


def _assert_refused(result: subprocess.CompletedProcess, code: str) -> None:
    assert result.returncode == 1, (
        f"expected FAIL: {code}; got exit {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}")
    assert re.match(rb"^FAIL: " + code.encode() + rb": ", result.stderr), result.stderr


def _assert_passed(result: subprocess.CompletedProcess) -> None:
    assert result.returncode == 0, (
        f"expected PASS; got exit {result.returncode}\nstderr: {result.stderr!r}")
    assert PASS_RE.match(result.stdout), result.stdout


@pytest.mark.parametrize("fixture", MLDSA_FIXTURES)
@pytest.mark.parametrize("index", [0, oca_constants.ML_DSA_87_SIGNATURE_BYTES - 1])
def test_cli_mldsa_rejects_a_flipped_signature_byte(tmp_path, fixture, index):
    """The first and last byte of the 4627-byte value both count."""
    data = _fixture_bytes(fixture)
    data[oca_constants.OFF_SIGNATURE_PQC + index] ^= 0x01
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_sig{index}"), "SIGNATURE")


@pytest.mark.parametrize("fixture", MLDSA_FIXTURES)
def test_cli_mldsa_rejects_a_flipped_signed_byte(tmp_path, fixture):
    data = _fixture_bytes(fixture)
    data[oca_constants.OFF_MANIFEST_IDENTIFIER] ^= 0x01
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_signed"), "SIGNATURE")


@pytest.mark.parametrize("fixture", HYBRID_FIXTURES)
@pytest.mark.parametrize("broken", ["classic", "pqc"])
def test_cli_hybrid_needs_both_signatures(tmp_path, fixture, broken):
    """One valid signature never carries a hybrid manifest."""
    data = _fixture_bytes(fixture)
    offset = (oca_constants.OFF_PQC_SIGNATURE_CLASSIC if broken == "classic"
              else oca_constants.OFF_SIGNATURE_PQC)
    data[offset + 8] ^= 0x01
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_{broken}"), "SIGNATURE")


def test_cli_mldsa_rejects_a_swapped_public_key(tmp_path):
    data = _fixture_bytes("pqc_secure_mldsa")
    data[_PUBLIC_KEY_PQC_SPAN] = _fresh_mldsa_key().public_key().public_bytes_raw()
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, "swapped_key"), "SIGNATURE")


def test_cli_mldsa_rejects_a_signature_spliced_from_another_manifest(tmp_path):
    """Both manifests are signed by the same key; the signature still binds to
    its own signed region."""
    donor = _fixture_bytes("pqc_hybrid_rsa")
    data = _fixture_bytes("pqc_secure_mldsa")
    data[_SIGNATURE_PQC_SPAN] = donor[_SIGNATURE_PQC_SPAN]
    _assert_refused(_run_bundle(tmp_path, data, "spliced"), "SIGNATURE")


def _signed_region_message(data: bytearray, construction: str) -> bytes:
    import hashlib

    region = bytes(data[:oca_constants.PQC_SIGNED_REGION_END])
    if construction == "sha256-prehash":
        return hashlib.sha256(region).digest()
    if construction == "sha512-prehash":
        return hashlib.sha512(region).digest()
    return region


def _harness_accepts_resigned(tmp_path, construction: str, context=None) -> bool:
    """Re-sign pqc_secure_mldsa with the development key under `construction`
    and report whether the CLI accepts it.

    Signs with the raw key rather than through the signing layer, which cannot
    produce a pre-hashed or context-bound signature and must not: those are the
    negative fixtures. The pure construction shares the path so the positive
    case exercises the same code as the refusals."""
    data = _fixture_bytes("pqc_secure_mldsa")
    message = _signed_region_message(data, construction)
    signature = (_mldsa_dev_key().sign(message) if context is None
                 else _mldsa_dev_key().sign(message, context))
    data[_SIGNATURE_PQC_SPAN] = signature
    result = _run_bundle(tmp_path, data, f"resigned_{construction}_{context!r}")
    if result.returncode == 0:
        return True
    _assert_refused(result, "SIGNATURE")
    return False


def test_cli_mldsa_accepts_pure_mldsa_over_the_region_with_the_empty_context(tmp_path):
    assert _harness_accepts_resigned(tmp_path, "pure")


@pytest.mark.parametrize("construction,context", [
    ("pure", b"OCA"),
    ("sha256-prehash", None),
    ("sha512-prehash", None),
])
def test_cli_mldsa_refuses_any_other_construction(tmp_path, construction, context):
    assert not _harness_accepts_resigned(tmp_path, construction, context)


# --- ROOT-key anchors, one per family ---


def test_cli_root_key_digest_pqc_authorizes_the_matching_key():
    _assert_passed(_run_cli(["--manifest", _pack_fixture("pqc_secure_mldsa"),
                             "--root-key-digest-pqc", _mldsa_dev_key_digest()]))


def test_cli_root_key_digest_pqc_refuses_another_key():
    other = _key_digest(_fresh_mldsa_key().public_key().public_bytes_raw())
    _assert_refused(_run_cli(["--manifest", _pack_fixture("pqc_secure_mldsa"),
                              "--root-key-digest-pqc", other]), "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("classic_anchor,pqc_anchor", [
    (True, True), (True, False), (False, True)])
def test_cli_hybrid_needs_an_anchor_for_each_family(classic_anchor, pqc_anchor):
    args = ["--manifest", _pack_fixture("pqc_hybrid_rsa")]
    if classic_anchor:
        args += ["--root-key-digest", _rsa_raw_key_digest(RSA_F4_KEY)]
    if pqc_anchor:
        args += ["--root-key-digest-pqc", _mldsa_dev_key_digest()]
    result = _run_cli(args)
    if classic_anchor and pqc_anchor:
        _assert_passed(result)
    else:
        _assert_refused(result, "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("fixture,flag,digest", [
    ("pqc_secure_mldsa", "--root-key-digest", "mldsa"),
    ("secure_rsa", "--root-key-digest-pqc", "rsa"),
])
def test_cli_root_key_anchors_do_not_cross_families(fixture, flag, digest):
    """Each family is authorized by its own anchor only, even one that matches."""
    value = _mldsa_dev_key_digest() if digest == "mldsa" else _rsa_raw_key_digest(RSA_F4_KEY)
    _assert_refused(_run_cli(["--manifest", _pack_fixture(fixture), flag, value]),
                    "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("bad_digest", ["ab" * 31, "zz" * 32, ""])
def test_cli_rejects_a_malformed_root_key_digest_pqc(bad_digest):
    result = _run_cli(["--manifest", _pack_fixture("pqc_secure_mldsa"),
                       "--root-key-digest-pqc", bad_digest])
    assert result.returncode == 2, result.stderr
    assert b"--root-key-digest-pqc" in result.stderr


def _mldsa_key_digest(key_path: str) -> str:
    return _key_digest(_public_key_of(key_path).public_bytes_raw())


# Fixtures whose .flags hold a real anchor rather than --trust-any-root-key, so
# the fixture sweep and the PASS-for-each-fixture test exercise the trust anchor
# for every key shape and both families.
_FIXTURE_ANCHORS = [
    ("secure_rsa", "--root-key-digest", "signing_key_file", _rsa_raw_key_digest),
    ("secure_rsa_der", "--root-key-digest", "signing_key_file", _rsa_der_key_digest),
    ("secure_ecdsa", "--root-key-digest", "signing_key_file", _ec_raw_key_digest),
    ("pqc_secure_mldsa", "--root-key-digest-pqc", "signing_key_file_pqc", _mldsa_key_digest),
    ("pqc_hybrid_ecdsa", "--root-key-digest", "signing_key_file", _ec_raw_key_digest),
    ("pqc_hybrid_ecdsa", "--root-key-digest-pqc", "signing_key_file_pqc", _mldsa_key_digest),
]


@pytest.mark.parametrize("fixture,flag,key_field,digest_of", _FIXTURE_ANCHORS)
def test_fixture_anchor_is_the_digest_of_the_key_it_signs_with(fixture, flag, key_field,
                                                              digest_of):
    """A committed anchor is pinned to the key its fixture's config names, so a
    key rotation fails here, naming the fixture, rather than in the sweep."""
    flags = _read_flags(fixture)
    assert "--trust-any-root-key" not in flags
    assert flag in flags, f"{fixture}.flags has no {flag}"
    cfg = load_config(os.path.join(FIXTURE_DIR, f"{fixture}.yaml"))
    expected = digest_of(os.path.join(PROJECT_ROOT, cfg[key_field]))
    assert flags[flags.index(flag) + 1] == expected


# --- The PQC signing description ---


@pytest.mark.parametrize("name,offset,width,value,code", [
    ("ml-dsa-65", oca_constants.OFF_SIGNATURE_TYPE_PQC, 1, 0x32, "ALGORITHM_NOT_ENABLED"),
    ("fn-dsa-512", oca_constants.OFF_SIGNATURE_TYPE_PQC, 1, 0x41, "ALGORITHM_RESERVED"),
    ("signature-size", oca_constants.OFF_SIGNATURE_SIZE_PQC, 2,
     oca_constants.ML_DSA_87_SIGNATURE_BYTES - 1, "CRYPTO_FIELD_SIZE"),
    ("key-size", oca_constants.OFF_PUBLIC_KEY_SIZE_PQC, 2,
     oca_constants.ML_DSA_87_PUBLIC_KEY_BYTES + 1, "CRYPTO_FIELD_SIZE"),
    ("signature-der", oca_constants.OFF_SIGNATURE_ENCODING_PQC, 1, 0x01, "CRYPTO_FIELD_SIZE"),
    ("key-der", oca_constants.OFF_PUBLIC_KEY_ENCODING_PQC, 1, 0x01, "CRYPTO_FIELD_SIZE"),
])
def test_cli_mldsa_refuses_a_description_it_cannot_verify(tmp_path, name, offset, width,
                                                          value, code):
    data = _fixture_bytes("pqc_secure_mldsa")
    _set_le(data, offset, width, value)
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, name), code)


# --- ROOT-key revocation, per family ---


def test_cli_mldsa_manifest_that_revokes_its_own_key_is_refused(tmp_path):
    data = _fixture_bytes("pqc_secure_mldsa")
    select = data[oca_constants.OFF_PUBLIC_KEY_SELECT_PQC:
                  oca_constants.OFF_PUBLIC_KEY_SELECT_PQC + 16]
    data[oca_constants.OFF_PUBLIC_KEY_PQC_REVOKE:
         oca_constants.OFF_PUBLIC_KEY_PQC_REVOKE + 16] = select
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, "self_revoked"), "ROOT_KEY_REVOKED")


# Every fixture selects slot 0 (bit 0) in each family it signs with.
_SLOT_0 = "0x01"
_SLOT_0_FULL_WIDTH = "0x" + "0" * 31 + "1"
_SLOT_127 = "0x8" + "0" * 31


@pytest.mark.parametrize("fixture,flag,bitmap,revoked", [
    ("pqc_secure_mldsa", "--revoked-root-keys-pqc", _SLOT_0, True),
    ("pqc_secure_mldsa", "--revoked-root-keys-pqc", _SLOT_0_FULL_WIDTH, True),
    ("pqc_secure_mldsa", "--revoked-root-keys-pqc", "0x02", False),
    ("pqc_secure_mldsa", "--revoked-root-keys-pqc", _SLOT_127, False),
    ("pqc_secure_mldsa", "--revoked-root-keys", _SLOT_0, False),
    ("pqc_hybrid_rsa", "--revoked-root-keys", _SLOT_0, True),
    ("pqc_hybrid_rsa", "--revoked-root-keys-pqc", _SLOT_0, True),
    ("pqc_secure_rsa", "--revoked-root-keys-pqc", _SLOT_0, False),
    ("secure_rsa", "--revoked-root-keys", _SLOT_0, True),
])
def test_cli_device_revocation_applies_to_its_own_family(fixture, flag, bitmap, revoked):
    result = _run_cli(["--manifest", _pack_fixture(fixture), "--trust-any-root-key",
                       flag, bitmap])
    if revoked:
        _assert_refused(result, "ROOT_KEY_REVOKED")
    else:
        _assert_passed(result)


@pytest.mark.parametrize("flag", ["--revoked-root-keys", "--revoked-root-keys-pqc"])
@pytest.mark.parametrize("bad_bitmap", ["", "0x", "0x" + "1" * 33, "zz"])
def test_cli_rejects_a_malformed_revocation_bitmap(flag, bad_bitmap):
    result = _run_cli(["--manifest", _pack_fixture("pqc_secure_mldsa"), flag, bad_bitmap])
    assert result.returncode == 2, result.stderr
    assert flag.encode() in result.stderr


def test_cli_help_documents_the_pqc_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    for flag in (b"--root-key-digest-pqc", b"--revoked-root-keys",
                 b"--revoked-root-keys-pqc"):
        assert flag in result.stdout, f"--help does not document {flag!r}"


def test_make_refuses_an_openssl_older_than_the_minimum():
    """The CLI link checks the discovered OpenSSL against the minimum, so an
    older one fails the build with the reason rather than at ML-DSA verify."""
    result = subprocess.run(
        ["make", "-C", VALIDATOR_DIR, "OPENSSL_MIN_VERSION=99.0.0", "test"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env={**os.environ, "PYTHON": sys.executable},
    )
    assert result.returncode != 0
    assert "99.0.0" in result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Anchors bind the whole key and its selected slot
#
# The anchor stands in for a digest a device holds per key slot. It must cover
# every byte the verifier uses, and it vouches only for a key whose own slot the
# manifest selects: revocation is decided from that select bitmap, so an anchor
# that ignored it would let a revoked key claim another slot and boot.
# ---------------------------------------------------------------------------

_RSA_KEY_FIELD = oca_constants.OFF_PUBLIC_KEY_CLASSIC
_RSA_EXPONENT_LAST_BYTE = _RSA_KEY_FIELD + oca_constants.RSA_3072_MODULUS_BYTES + 3


@pytest.mark.parametrize("offset", [_RSA_KEY_FIELD, _RSA_EXPONENT_LAST_BYTE],
                         ids=["modulus", "exponent"])
def test_cli_root_key_digest_covers_the_whole_raw_key(tmp_path, offset):
    """Any byte of the raw key — exponent included — changes what the anchor
    sees, so the genuine digest no longer authorizes it."""
    data = _fixture_bytes("secure_rsa")
    data[offset] ^= 0x02
    _reseal_manifest_hash(data)
    result = _run_bundle(tmp_path, data, f"altered_key_{offset}",
                         flags=("--root-key-digest", _rsa_raw_key_digest(RSA_F4_KEY)))
    _assert_refused(result, "ROOT_KEY_UNAUTHORIZED")


def _pack_with(tmp_path, fixture: str, **overrides) -> str:
    """Pack a fixture config with some fields overridden, in process."""
    cfg = load_config(os.path.join(FIXTURE_DIR, f"{fixture}.yaml"))
    cfg.update(overrides)
    prev = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        bundle = pack_oca_bundle(cfg)
    finally:
        os.chdir(prev)
    path = tmp_path / f"{fixture}_override.bin"
    path.write_bytes(bundle)
    return str(path)


@pytest.mark.parametrize("anchor_slot,passes", [("", True), ("0:", True), ("1:", False)])
def test_cli_pqc_anchor_vouches_only_for_its_own_slot(anchor_slot, passes):
    """pqc_secure_mldsa selects slot 0, so only a slot-0 anchor authorizes it."""
    result = _run_cli(["--manifest", _pack_fixture("pqc_secure_mldsa"),
                       "--root-key-digest-pqc", anchor_slot + _mldsa_dev_key_digest()])
    if passes:
        _assert_passed(result)
    else:
        _assert_refused(result, "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("fixture,flag,select_field,digest", [
    ("pqc_secure_mldsa", "--root-key-digest-pqc", "public_key_select_pqc", "mldsa"),
    ("secure_rsa", "--root-key-digest", "public_key_select_classic", "rsa"),
])
def test_cli_a_key_claiming_another_slot_is_unauthorized(tmp_path, fixture, flag,
                                                         select_field, digest):
    """The slot-0 key, re-packed claiming slot 1, matches the slot-0 digest but
    not the slot it claims."""
    value = _mldsa_dev_key_digest() if digest == "mldsa" else _rsa_raw_key_digest(RSA_F4_KEY)
    bundle = _pack_with(tmp_path, fixture, **{select_field: 0x02})
    _assert_refused(_run_cli(["--manifest", bundle, flag, value]), "ROOT_KEY_UNAUTHORIZED")
    _assert_passed(_run_cli(["--manifest", bundle, flag, "1:" + value]))


def test_cli_a_revoked_key_cannot_escape_by_claiming_another_slot(tmp_path):
    """The device has revoked slot 0. Its key, re-signed claiming slot 1, is
    refused: the anchor holds that key at slot 0, which the manifest no longer
    selects, and slot 1's revocation bit is clear."""
    bundle = _pack_with(tmp_path, "pqc_secure_mldsa", public_key_select_pqc=0x02)
    result = _run_cli(["--manifest", bundle,
                       "--root-key-digest-pqc", _mldsa_dev_key_digest(),
                       "--revoked-root-keys-pqc", "0x1"])
    _assert_refused(result, "ROOT_KEY_UNAUTHORIZED")


def _resign_pqc(data: bytearray, fixture: str) -> None:
    """Re-seal manifest_hash and re-sign the PQC class through the signing layer,
    with the key `fixture`'s config names, so an edit to the signed region
    survives the integrity and signature checks."""
    _reseal_manifest_hash(data)
    cfg = load_config(os.path.join(FIXTURE_DIR, f"{fixture}.yaml"))
    prev = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        signing_key = build_pqc_signing_key(cfg)
    finally:
        os.chdir(prev)
    region = bytes(data[:oca_constants.PQC_SIGNED_REGION_END])
    start = oca_constants.OFF_SIGNATURE_PQC
    data[start:start + oca_constants.LEN_SIGNATURE_PQC] = sign_signed_region_pqc(
        region, signing_key, oca_constants.ML_DSA_87_SIGNATURE_BYTES)


def test_cli_an_enforced_class_that_selects_no_key_is_unauthorized(tmp_path):
    """Refused by the library before any anchor is asked, so even
    --trust-any-root-key cannot authorize a class that selects nothing."""
    data = _fixture_bytes("pqc_secure_mldsa")
    off = oca_constants.OFF_PUBLIC_KEY_SELECT_PQC
    data[off:off + 16] = bytes(16)
    _resign_pqc(data, "pqc_secure_mldsa")
    _assert_refused(_run_bundle(tmp_path, data, "select_none"), "ROOT_KEY_UNAUTHORIZED")


@pytest.mark.parametrize("bad", ["112:" + "ab" * 32, "99999:" + "ab" * 32, "1:" + "ab" * 31])
@pytest.mark.parametrize("flag", ["--root-key-digest", "--root-key-digest-pqc"])
def test_cli_rejects_a_malformed_anchor_slot(flag, bad):
    result = _run_cli(["--manifest", _pack_fixture("basic"), flag, bad])
    assert result.returncode == 2, result.stderr
    assert flag.encode() in result.stderr


# ---------------------------------------------------------------------------
# Declared sizes bound every key and signature
#
# A key or signature field holds its value at the start and zero padding past
# the declared size. The library refuses a non-zero padding byte: a signature
# field lies outside the signed region, so anything else there would make
# byte-distinct bundles of one signed manifest. The reference backend parses a
# DER value within its declared size: a DER key must fill it exactly, and a DER
# ECDSA signature may be followed only by zeros up to its declared maximum.
# ---------------------------------------------------------------------------


def _resign_classic(data: bytearray, fixture: str) -> None:
    """Re-seal manifest_hash and re-sign the classical class through the signing
    layer, with the key `fixture`'s config names and the encoding and declared
    size the body already carries, so an edit to the signed region survives the
    integrity and signature checks."""
    _reseal_manifest_hash(data)
    if bytes(data[:4]) == oca_constants.OCAP_MAGIC:
        region_end = oca_constants.PQC_SIGNED_REGION_END
        start = oca_constants.OFF_PQC_SIGNATURE_CLASSIC
    else:
        region_end = oca_constants.OCA_CLASSIC_SIGNED_REGION_END
        start = oca_constants.OFF_SIGNATURE_CLASSIC
    cfg = load_config(os.path.join(FIXTURE_DIR, f"{fixture}.yaml"))
    prev = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        signing_key = build_signing_key(cfg)
    finally:
        os.chdir(prev)
    encoding = data[oca_constants.OFF_SIGNATURE_ENCODING_CLASSIC]
    declared = struct.unpack_from("<H", data, oca_constants.OFF_SIGNATURE_SIZE_CLASSIC)[0]
    data[start:start + oca_constants.SIGNATURE_CLASSIC_SIZE] = sign_signed_region(
        bytes(data[:region_end]), signing_key, encoding, declared)


def _with_public_key_size_classic(fixture: str, delta: int) -> bytearray:
    """`fixture` with public_key_size_classic moved by `delta`, re-signed."""
    data = _fixture_bytes(fixture)
    declared = struct.unpack_from("<H", data, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    _set_le(data, oca_constants.OFF_PUBLIC_KEY_SIZE_CLASSIC, 2, declared + delta)
    _resign_classic(data, fixture)
    return data


@pytest.mark.parametrize("fixture", ["secure_rsa_der", "secure_ecdsa", "pqc_hybrid_rsa"])
def test_cli_a_resigned_classical_bundle_still_verifies(tmp_path, fixture):
    """The control for every re-signed refusal below: re-signing alone changes
    nothing a verifier objects to."""
    _assert_passed(_run_bundle(tmp_path, _with_public_key_size_classic(fixture, 0),
                               f"{fixture}_resigned"))


@pytest.mark.parametrize("fixture", ["secure_rsa_der", "secure_rsa_e3_der"])
def test_cli_refuses_a_der_key_shorter_than_its_declared_size(tmp_path, fixture):
    """public_key_size_classic two bytes past the end of the DER key, correctly
    re-signed. The two extra bytes are zero padding, so only the backend's rule
    that a DER key fills its declared size exactly catches it — run with any
    key trusted, since an anchor over the declared bytes would refuse first."""
    data = _with_public_key_size_classic(fixture, +2)
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_size_plus_2"), "SIGNATURE")


@pytest.mark.parametrize("fixture", ["secure_rsa_der", "secure_rsa_e3_der"])
def test_cli_refuses_a_der_key_longer_than_its_declared_size(tmp_path, fixture):
    """public_key_size_classic two bytes short of the DER key: its last two
    bytes lie past the declared size, where only zero padding may be."""
    data = _with_public_key_size_classic(fixture, -2)
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_size_minus_2"),
                    "CRYPTO_FIELD_SIZE")


@pytest.mark.parametrize("fixture,offset,value", [
    ("secure_rsa", oca_constants.OFF_PUBLIC_KEY_ENCODING_CLASSIC, 0x00),
    ("secure_rsa_der", oca_constants.OFF_PUBLIC_KEY_ENCODING_CLASSIC, 0xF0),
    ("secure_ecdsa", oca_constants.OFF_SIGNATURE_ENCODING_CLASSIC, 0x03),
], ids=["rsa-key-unset", "rsa-key-integrator", "ecdsa-signature-reserved"])
def test_cli_refuses_a_classical_encoding_its_primitive_does_not_define(tmp_path, fixture,
                                                                       offset, value):
    """An encoding outside the ones the primitive defines is refused by the
    library, before any callback, rather than read under another encoding's
    rule and left for the crypto backend to reject."""
    data = _fixture_bytes(fixture)
    data[offset] = value
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_encoding_{value:#04x}"),
                    "CRYPTO_FIELD_SIZE")


# (fixture, field offset, declared valid bytes, field width). The signature
# fields are unsigned, so these need no re-seal; the key fields are signed.
_SIGNATURE_FIELDS = [
    ("secure_rsa", oca_constants.OFF_SIGNATURE_CLASSIC, 384,
     oca_constants.SIGNATURE_CLASSIC_SIZE),
    ("secure_ecdsa", oca_constants.OFF_SIGNATURE_CLASSIC, 64,
     oca_constants.SIGNATURE_CLASSIC_SIZE),
    ("pqc_hybrid_rsa", oca_constants.OFF_PQC_SIGNATURE_CLASSIC, 384,
     oca_constants.SIGNATURE_CLASSIC_SIZE),
    ("pqc_secure_mldsa", oca_constants.OFF_SIGNATURE_PQC,
     oca_constants.ML_DSA_87_SIGNATURE_BYTES, oca_constants.LEN_SIGNATURE_PQC),
]
_PUBLIC_KEY_FIELDS = [
    ("secure_rsa", oca_constants.OFF_PUBLIC_KEY_CLASSIC, 388,
     oca_constants.PUBLIC_KEY_CLASSIC_SIZE),
    ("secure_rsa_der", oca_constants.OFF_PUBLIC_KEY_CLASSIC, 398,
     oca_constants.PUBLIC_KEY_CLASSIC_SIZE),
    ("secure_ecdsa", oca_constants.OFF_PUBLIC_KEY_CLASSIC, 65,
     oca_constants.PUBLIC_KEY_CLASSIC_SIZE),
    ("pqc_secure_mldsa", oca_constants.OFF_PUBLIC_KEY_PQC,
     oca_constants.ML_DSA_87_PUBLIC_KEY_BYTES, oca_constants.LEN_PUBLIC_KEY_PQC),
]


def _padding_ids(cases) -> list:
    return [f"{fixture}@{offset}" for fixture, offset, _valid, _width in cases]


@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("fixture,offset,valid,width", _SIGNATURE_FIELDS,
                         ids=_padding_ids(_SIGNATURE_FIELDS))
def test_cli_refuses_a_signature_whose_padding_is_not_zero(tmp_path, fixture, offset,
                                                          valid, width, position):
    data = _fixture_bytes(fixture)
    assert not any(data[offset + valid:offset + width]), "the packer pads with zeros"
    data[offset + (valid if position == "first" else width - 1)] = 0x01
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_sig_pad_{position}"),
                    "CRYPTO_FIELD_SIZE")


@pytest.mark.parametrize("position", ["first", "last"])
@pytest.mark.parametrize("fixture,offset,valid,width", _PUBLIC_KEY_FIELDS,
                         ids=_padding_ids(_PUBLIC_KEY_FIELDS))
def test_cli_refuses_a_public_key_whose_padding_is_not_zero(tmp_path, fixture, offset,
                                                           valid, width, position):
    data = _fixture_bytes(fixture)
    assert not any(data[offset + valid:offset + width]), "the packer pads with zeros"
    data[offset + (valid if position == "first" else width - 1)] = 0x01
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, f"{fixture}_key_pad_{position}"),
                    "CRYPTO_FIELD_SIZE")


_DER_ECDSA_MAXIMUM = oca_constants.CLASSIC_DER_SIGNATURE_MAX_LENGTHS[
    oca_constants.OcaClassicSignatureType.ECDSA_P256_SHA256.value]


def _der_ecdsa_bundle_with_slack() -> tuple:
    """A DER ECDSA bundle whose signature is shorter than the declared maximum,
    and that signature's DER length."""
    for timestamp, der_len, _ends_in_zero in _ecdsa_sweep():
        if 0 < der_len < _DER_ECDSA_MAXIMUM:
            return bytearray(_ecdsa_bundle_for_timestamp(timestamp)), der_len
    pytest.fail("no DER ECDSA signature in the sweep is shorter than its maximum")


@pytest.mark.parametrize("position", ["first", "last"])
def test_cli_refuses_a_der_ecdsa_signature_followed_by_non_zero_bytes(tmp_path, position):
    """Between the DER value's end and the declared maximum the field is
    padding, which only the backend can locate, since only it reads the DER
    framing. The bytes are unsigned, so anything but zero there is refused."""
    bundle, der_len = _der_ecdsa_bundle_with_slack()
    index = der_len if position == "first" else _DER_ECDSA_MAXIMUM - 1
    bundle[_SIGNATURE_OFFSET + index] = 0x01
    result = _validate_bundle(bytes(bundle), tmp_path, f"ecdsa_slack_{position}")
    _assert_refused(result, "SIGNATURE")


def test_cli_refuses_a_der_ecdsa_signature_with_bytes_past_its_maximum(tmp_path):
    bundle, _der_len = _der_ecdsa_bundle_with_slack()
    bundle[_SIGNATURE_OFFSET + _DER_ECDSA_MAXIMUM] = 0x01
    result = _validate_bundle(bytes(bundle), tmp_path, "ecdsa_past_maximum")
    _assert_refused(result, "CRYPTO_FIELD_SIZE")


# ---------------------------------------------------------------------------
# Declared algorithms the library cannot compute
#
# manifest_hash_type and payload_hash_type name the digests, and an encrypted
# payload names its key derivation and input-key source. This build computes
# SHA2-256 and derives from the pre-shared secret through SP 800-108r1 with
# HMAC-SHA-256; anything else is refused by name rather than hashed or
# decrypted as if it were.
# ---------------------------------------------------------------------------

_SHA2_384 = 0x02
_SHAKE256_512 = 0x08


def test_cli_refuses_digests_it_does_not_compute_even_when_resealed_as_sha256(tmp_path):
    """A manifest declaring SHA2-384 and SHAKE256-512, with manifest_hash
    recomputed as SHA-256: a Consumer that honours the declared types rejects
    it, so this one must too."""
    data = _fixture_bytes("basic")
    data[oca_constants.OFF_MANIFEST_HASH_TYPE] = _SHA2_384
    data[oca_constants.OFF_PAYLOAD_HASH_TYPE] = _SHAKE256_512
    _reseal_manifest_hash(data)
    _assert_refused(_run_bundle(tmp_path, data, "declared_sha384", flags=()),
                    "ALGORITHM_NOT_ENABLED")


@pytest.mark.parametrize("fixture,offset,value", [
    ("basic", oca_constants.OFF_MANIFEST_HASH_TYPE, _SHA2_384),
    ("pqc_basic", oca_constants.OFF_MANIFEST_HASH_TYPE, _SHA2_384),
    ("basic", oca_constants.OFF_PAYLOAD_HASH_TYPE, _SHAKE256_512),
    ("pqc_basic", oca_constants.OFF_PAYLOAD_HASH_TYPE, 0x00),
], ids=["manifest-classic", "manifest-pqc", "payload-classic", "payload-pqc-unset"])
def test_cli_refuses_an_unsupported_hash_type(tmp_path, fixture, offset, value):
    data = _fixture_bytes(fixture)
    data[offset] = value
    _reseal_manifest_hash(data)
    result = _run_bundle(tmp_path, data, f"{fixture}_hash_type_{offset}", flags=())
    _assert_refused(result, "ALGORITHM_NOT_ENABLED")
    assert not result.stderr.rstrip().endswith(b": ok"), result.stderr


def _encrypted_with(field: str, value: int) -> bytearray:
    """encrypted_aes with one encryption field changed, re-signed so the edit
    survives the integrity and signature checks."""
    data = _fixture_bytes("encrypted_aes")
    if field == "kdf":
        _set_le(data, oca_constants.OFF_ENCRYPTION_KDF, 2, value)
    elif field == "cipher":
        data[oca_constants.OFF_ENCRYPTION_TYPE] = value
    else:
        control = struct.unpack_from("<H", data,
                                     oca_constants.OFF_PAYLOAD_ENCRYPTION_CONTROL)[0]
        shift = oca_constants.ENCRYPTION_INPUT_KEY_SOURCE_SHIFT
        control = (control & ~(0x7 << shift)) | (value << shift)
        _set_le(data, oca_constants.OFF_PAYLOAD_ENCRYPTION_CONTROL, 2, control)
    _resign_classic(data, "encrypted_aes")
    return data


def test_cli_a_resigned_encrypted_bundle_still_decrypts(tmp_path):
    """The control for the refusals below: re-signing with the supported KDF and
    key source changes nothing."""
    data = _encrypted_with("kdf", oca_constants.OcaEncryptionKdf.SP800_108_CTR_HMAC_SHA256.value)
    _assert_passed(_run_bundle(tmp_path, data, "encrypted_resigned",
                               flags=_read_flags("encrypted_aes")))


@pytest.mark.parametrize("field,value,code", [
    ("kdf", 0x0000, "ALGORITHM_NOT_ENABLED"),       # NONE: the input key used directly
    ("kdf", 0x0002, "ALGORITHM_NOT_ENABLED"),       # SP 800-108r1 with HMAC-SHA-512
    ("kdf", 0xFF00, "ALGORITHM_NOT_ENABLED"),       # integrator defined
    ("kdf", 0x0009, "ALGORITHM_RESERVED"),
    ("key_source", 0b010, "ALGORITHM_NOT_ENABLED"),  # a KEM-unwrapped DEK
    ("key_source", 0b000, "ALGORITHM_RESERVED"),     # no source selected
    ("key_source", 0b011, "ALGORITHM_RESERVED"),     # two sources at once
    ("cipher", 0x03, "ALGORITHM_NOT_ENABLED"),       # AES-128-CBC-HMAC-SHA256
    ("cipher", 0x05, "ALGORITHM_NOT_ENABLED"),       # AES-128-GCM-SIV
    ("cipher", 0x13, "ALGORITHM_RESERVED"),
])
def test_cli_refuses_an_encrypted_payload_it_cannot_derive_a_key_for(tmp_path, field,
                                                                      value, code):
    """The reference backend always derives through SP 800-108r1 HMAC-SHA-256
    from the pre-shared secret, so without this refusal a manifest naming any
    other derivation decrypts as if it named that one."""
    data = _encrypted_with(field, value)
    result = _run_bundle(tmp_path, data, f"encrypted_{field}_{value:#x}",
                         flags=_read_flags("encrypted_aes"))
    _assert_refused(result, code)


def _unreachable_openssl_minimum() -> str:
    """An OpenSSL minimum no host meets."""
    return "99.0.0"


def test_an_openssl_below_the_minimum_is_a_reason_naming_both_versions(monkeypatch):
    """On a host whose OpenSSL is too old the suite skips — or, with
    TT_BOOT_MANIFEST_REQUIRE_VALIDATOR set, fails — saying what it needs and
    what it found."""
    monkeypatch.setattr(sys.modules[__name__], "_openssl_min_version",
                        _unreachable_openssl_minimum)
    reason = _validator_unavailable_reason()
    assert reason is not None
    assert "99.0.0" in reason and "pkg-config reports" in reason


# ---------------------------------------------------------------------------
# The device's signature posture
#
# --signature-class-revoke and --signature-cohort-enforce stand in for the
# device-stored registers earlier manifests OR-ed into. Applied at boot: an
# algorithm the device has disabled refuses any manifest that relies on it, and
# a cohort the device demands of the ROOT key's signatures must be enforced.
# ---------------------------------------------------------------------------

_ML_DSA_87_DISABLED = hex(1 << 26)
_RSA_3072_DISABLED = hex(1 << 0)
_P256_DISABLED = hex(1 << 2)
_PQC_GROUP_DISABLED = hex(0xAC << 32)
_CLASSICAL_GROUP_DISABLED = hex(0xCA << 8)
_ROOT_DEMANDS_CLASSICAL = "0x1"
_ROOT_DEMANDS_PQC = "0x2"


def _run_with_posture(fixture: str, *, revoke: str = "0x0", cohort: str = "0x0",
                      extra=()) -> subprocess.CompletedProcess:
    return _run_cli(["--manifest", _pack_fixture(fixture), *_read_flags(fixture),
                     "--signature-class-revoke", revoke,
                     "--signature-cohort-enforce", cohort, *extra])


@pytest.mark.parametrize("fixture,revoke,refused", [
    ("pqc_secure_mldsa", _ML_DSA_87_DISABLED, True),
    ("pqc_hybrid_rsa", _ML_DSA_87_DISABLED, True),
    ("pqc_secure_rsa", _ML_DSA_87_DISABLED, False),
    ("secure_rsa", _RSA_3072_DISABLED, True),
    ("secure_ecdsa", _RSA_3072_DISABLED, False),
    ("secure_ecdsa", _P256_DISABLED, True),
    ("pqc_hybrid_ecdsa", _P256_DISABLED, True),
    ("pqc_secure_mldsa", _PQC_GROUP_DISABLED, True),
    ("pqc_secure_rsa", _PQC_GROUP_DISABLED, False),
    ("pqc_secure_rsa", _CLASSICAL_GROUP_DISABLED, True),
    ("pqc_secure_mldsa", _CLASSICAL_GROUP_DISABLED, False),
])
def test_cli_a_disabled_algorithm_refuses_the_manifests_relying_on_it(fixture, revoke, refused):
    result = _run_with_posture(fixture, revoke=revoke)
    if refused:
        _assert_refused(result, "SIGNATURE_ALGORITHM_REVOKED")
    else:
        _assert_passed(result)


@pytest.mark.parametrize("fixture,cohort,revoke,refused", [
    ("pqc_secure_rsa", _ROOT_DEMANDS_PQC, "0x0", True),
    ("secure_rsa", _ROOT_DEMANDS_PQC, "0x0", True),
    ("pqc_secure_mldsa", _ROOT_DEMANDS_PQC, "0x0", False),
    ("pqc_hybrid_rsa", _ROOT_DEMANDS_PQC, "0x0", False),
    ("pqc_secure_mldsa", _ROOT_DEMANDS_CLASSICAL, "0x0", True),
    ("pqc_hybrid_rsa", "0x3", "0x0", False),
    ("pqc_secure_rsa", _ROOT_DEMANDS_PQC, _PQC_GROUP_DISABLED, False),
    ("pqc_secure_rsa", "0x3333333330", "0x0", False),
], ids=["classic-only-ocap", "classic", "pqc-only", "hybrid", "pqc-only-classical-demanded",
        "hybrid-both-demanded", "demand-withdrawn-by-group", "unengaged-entities"])
def test_cli_a_demanded_cohort_must_be_enforced(fixture, cohort, revoke, refused):
    """A disabled group withdraws its cohort demand, and bits for the verifier
    key and co-signers — entities this library does not engage — demand
    nothing."""
    result = _run_with_posture(fixture, cohort=cohort, revoke=revoke)
    if refused:
        _assert_refused(result, "SIGNATURE_COHORT_REQUIRED")
    else:
        _assert_passed(result)


def test_cli_the_posture_is_inert_for_a_non_secure_manifest():
    _assert_passed(_run_with_posture("pqc_basic", revoke="0xffffffffff", cohort="0xff"))


@pytest.mark.parametrize("fixture,revoke,refused", [
    ("pqc_secure_mldsa", _ML_DSA_87_DISABLED, True),
    ("pqc_secure_mldsa", _RSA_3072_DISABLED, False),
])
def test_cli_the_posture_applies_in_storage_mode(fixture, revoke, refused):
    result = _run_with_posture(fixture, revoke=revoke, extra=("--manifest-addr", "0"))
    if refused:
        _assert_refused(result, "SIGNATURE_ALGORITHM_REVOKED")
    else:
        _assert_passed(result)


@pytest.mark.parametrize("flag", ["--signature-cohort-enforce", "--signature-class-revoke"])
@pytest.mark.parametrize("bad", ["", "0x", "0x" + "1" * 17, "zz"])
def test_cli_rejects_a_malformed_posture_register(flag, bad):
    result = _run_cli(["--manifest", _pack_fixture("basic"), flag, bad])
    assert result.returncode == 2, result.stderr
    assert flag.encode() in result.stderr


def test_cli_help_documents_the_posture_flags():
    result = _run_cli(["--help"])
    assert result.returncode == 0
    for flag in (b"--signature-cohort-enforce", b"--signature-class-revoke"):
        assert flag in result.stdout, f"--help does not document {flag!r}"

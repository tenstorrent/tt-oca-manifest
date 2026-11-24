# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The library's algorithm code points, against the generator's.

Every value of every algorithm field is resolved by the compiled library and
held to the generator's lists and the format's integrator ranges, under each
configuration.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from tt_boot_manifest.oca import constants as oca_constants
from oca_fixtures.generator import (LIB_DIR, DEFAULT_CONFIG, gen_config,
                                    UNIT_TEST_CONFIGURATIONS, config_text, write_config,
                                    default_header, require_tools)
from oca_fixtures.toolchain import C_COMPILER


# The values the format leaves to integrators in each algorithm field: defined,
# so "not enabled" rather than "reserved". The hash types have none, nor does
# input_key_source.
INTEGRATOR_DEFINED = {
    "signature_classic": range(0xF0, 0x100),
    "signature_pqc": range(0xF0, 0x100),
    "hash": range(0),
    "encryption_cipher": range(0xF0, 0x100),
    "encryption_kdf": range(0xFF00, 0x10000),
    "encryption_key_source": range(0),
}

# Every value each field can hold.
FIELD_VALUES = {
    "signature_classic": range(0x100),
    "signature_pqc": range(0x100),
    "hash": range(0x100),
    "encryption_cipher": range(0x100),
    "encryption_kdf": range(0x10000),
    "encryption_key_source": range(8),
}

# Every value the probe resolves for a field of each width: the byte fields and
# the three-bit key source are carried in uint16_t crypto types, so the probe
# also resolves the values past each field, which the format reserves.
BYTE_FIELD_PROBE_END = 0x200
KEY_SOURCE_PROBE_END = 0x10
PROBED_VALUES = {
    "signature_classic": range(BYTE_FIELD_PROBE_END),
    "signature_pqc": range(BYTE_FIELD_PROBE_END),
    "hash": range(BYTE_FIELD_PROBE_END),
    "encryption_cipher": range(BYTE_FIELD_PROBE_END),
    "encryption_kdf": range(0x10000),
    "encryption_key_source": range(KEY_SOURCE_PROBE_END),
}

# How each class's signature and public-key encodings resolve, from the
# packer's lists: "on" for an encoding the class defines (whether the
# algorithm defines it, and whether the build enables a DER it defines, are the
# row's to say), "off" for an integrator encoding, and "reserved" otherwise.
ENCODING_FIELDS = {
    "encoding_classic": oca_constants.OCA_SELECTABLE_ENCODINGS,
    "encoding_pqc": oca_constants.PQC_SELECTABLE_ENCODINGS,
}

# The format reserves FN-DSA's two values until FIPS 206 is published, but
# already gives FN-DSA a signature_class_revoke bit.
REVOCABLE_WHILE_RESERVED = {"signature_pqc": {0x41, 0x42}}

# Prints how the library resolves every value of every algorithm field, and the
# values PROBED_VALUES adds past it, and the signature_class_revoke bit the
# posture check gives each signature type.
# signature_posture.c is included rather than linked: its maps are file-local.
CODE_POINT_PROBE = r"""
#include <stdio.h>

#include "algorithms.h"
#include "signature_posture.c"

static const char *verdict(oca_result_t status, int has_row)
{
    if (status == OCA_OK && has_row) {
        return "on";
    }
    if (status == OCA_FAIL_ALGORITHM_NOT_ENABLED && !has_row) {
        return "off";
    }
    if (status == OCA_FAIL_ALGORITHM_RESERVED && !has_row) {
        return "reserved";
    }
    return "inconsistent";
}

int main(void)
{
    oca_result_t status;
    int row;
    for (unsigned v = 0u; v < BYTE_FIELD_PROBE_END; ++v) {
#if !OCA_CFG_SECURE_BOOT_DISABLED
        const oca_primitive_type_t type = (oca_primitive_type_t)v;
        row = oca_signature_algorithm(OCA_KEY_ALGO_CLASSIC, type, &status) != 0;
        printf("signature_classic %u %s\n", v, verdict(status, row));
        row = oca_signature_algorithm(OCA_KEY_ALGO_PQC, type, &status) != 0;
        printf("signature_pqc %u %s\n", v, verdict(status, row));
        status = oca_encoding_status(OCA_KEY_ALGO_CLASSIC, (oca_encoding_t)v);
        printf("encoding_classic %u %s\n", v, verdict(status, status == OCA_OK));
        status = oca_encoding_status(OCA_KEY_ALGO_PQC, (oca_encoding_t)v);
        printf("encoding_pqc %u %s\n", v, verdict(status, status == OCA_OK));
        printf("revoke signature_classic %u %d\n", v, classical_revoke_bit(type));
        printf("revoke signature_pqc %u %d\n", v, pqc_revoke_bit(type));
#endif
        row = oca_hash_algorithm((oca_hash_type_t)v, &status) != 0;
        printf("hash %u %s\n", v, verdict(status, row));
        row = oca_cipher_algorithm((oca_encryption_type_t)v, &status) != 0;
        printf("encryption_cipher %u %s\n", v, verdict(status, row));
    }
    for (unsigned v = 0u; v <= 0xFFFFu; ++v) {
        status = oca_kdf_status((oca_kdf_t)v);
        printf("encryption_kdf %u %s\n", v, verdict(status, status == OCA_OK));
    }
    for (unsigned v = 0u; v < KEY_SOURCE_PROBE_END; ++v) {
        status = oca_key_source_status((oca_key_source_t)v);
        printf("encryption_key_source %u %s\n", v, verdict(status, status == OCA_OK));
    }
    return 0;
}
"""


def resolve_every_code_point(tmp_path, header_text, lib_dir=LIB_DIR):
    """Run the code-point probe against a library built with header_text.

    Returns ({(field, value): verdict}, {(field, value): revoke bit}).
    """
    require_tools(C_COMPILER[0])
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    (gen / "oca_config.h").write_text(header_text)
    probe = tmp_path / "code_points.c"
    probe.write_text(CODE_POINT_PROBE)
    binary = tmp_path / "code_points"
    sources = [os.path.join(lib_dir, name) for name in sorted(os.listdir(lib_dir))
               if name.endswith(".c") and name != "signature_posture.c"]
    built = subprocess.run(
        [*C_COMPILER, "-std=c99", "-Wall", "-Werror", "-pedantic", "-I", str(lib_dir),
         "-I", str(gen), f"-DBYTE_FIELD_PROBE_END={BYTE_FIELD_PROBE_END:#x}u",
         f"-DKEY_SOURCE_PROBE_END={KEY_SOURCE_PROBE_END:#x}u",
         str(probe), *sources, "-o", str(binary)],
        capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    printed = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    verdicts, revoke_bits = {}, {}
    for line in printed.stdout.splitlines():
        words = line.split()
        if words[0] == "revoke":
            revoke_bits[(words[1], int(words[2]))] = int(words[3])
        else:
            verdicts[(words[0], int(words[1]))] = words[2]
    return verdicts, revoke_bits


def expected_verdicts(values):
    """How the generator's lists, and the integrator ranges, say every value of
    every field resolves under a configuration's resolved settings. A build
    that declares [secure_boot] disabled compiles out the signature and
    encoding lookups, so their fields are not resolved there."""
    expected = {}
    secure_boot_built = not values["OCA_CFG_SECURE_BOOT_DISABLED"]
    for field, probed in PROBED_VALUES.items():
        if field.startswith("signature_") and not secure_boot_built:
            continue
        settings = [s for s in gen_config.SETTINGS if s.section == field]
        defined = {s.code for s in settings} | set(INTEGRATOR_DEFINED[field])
        enabled = {s.code for s in settings if s.implemented and values[s.macro]}
        for value in probed:
            expected[(field, value)] = ("reserved" if value not in FIELD_VALUES[field]
                                        else "on" if value in enabled
                                        else "off" if value in defined
                                        else "reserved")
    for field, selectable in ENCODING_FIELDS.items():
        if not secure_boot_built:
            continue
        for value in range(BYTE_FIELD_PROBE_END):
            expected[(field, value)] = (
                "reserved" if value > 0xFF
                else "on" if value in selectable
                else "off" if value in oca_constants.INTEGRATOR_ENCODINGS
                else "reserved")
    return expected


def code_point_disagreements(verdicts, revoke_bits, values):
    """Every value the library resolves differently from the generator, and
    every signature type whose revocation bit disagrees with its definition."""
    expected = expected_verdicts(values)
    problems = [f"{field} 0x{value:X}: library {verdicts.get((field, value))}, "
                f"generator {want}"
                for (field, value), want in sorted(expected.items())
                if verdicts.get((field, value)) != want]
    for (field, value), bit in sorted(revoke_bits.items()):
        defined = expected[(field, value)] != "reserved"
        revocable = defined or value in REVOCABLE_WHILE_RESERVED.get(field, ())
        if (bit >= 0) != revocable:
            problems.append(f"{field} 0x{value:X}: revocation bit {bit}, but the "
                            f"format {'defines' if defined else 'reserves'} it")
    return problems


CODE_POINT_CONFIGURATIONS = [pytest.param(param.values[0], id=param.id)
                             for param in UNIT_TEST_CONFIGURATIONS]


@pytest.mark.parametrize("changes", CODE_POINT_CONFIGURATIONS)
def test_the_library_resolves_every_code_point_as_the_generator_lists_it(
        tmp_path, changes):
    """The format's code points are written out in the generator, in the
    library's tables and predicates, and in the posture check's revocation
    maps. Every value of every field is resolved by the compiled library and
    held to the generator's lists, under each configuration."""
    config = write_config(tmp_path, config_text(**changes))
    document = gen_config.load_config(config)
    values = gen_config.resolve_settings(document)
    verdicts, revoke_bits = resolve_every_code_point(
        tmp_path, gen_config.header_for_config(config))
    assert code_point_disagreements(verdicts, revoke_bits, values) == []


@pytest.mark.parametrize("source, edit, disagreement", [
    pytest.param("algorithms.c", ("|| type == 0x11u || type == 0x12u", "|| type == 0x11u"),
                 "encryption_cipher 0x12: library reserved, generator off",
                 id="a-defined-cipher-reserved"),
    pytest.param("algorithms.c", ("(type >= 0x01u && type <= 0x08u)",
                                  "(type >= 0x01u && type <= 0x09u)"),
                 "hash 0x9: library off, generator reserved",
                 id="a-reserved-hash-defined"),
    pytest.param("algorithms.c", ("&& family != OCA_KEY_ALGO_PQC", ""),
                 "encoding_pqc 0x1: library on, generator reserved",
                 id="a-reserved-encoding-defined"),
    pytest.param("signature_posture.c", ("case 0x0Bu:             return 6;", ""),
                 "signature_classic 0xB: revocation bit -1, but the format defines it",
                 id="a-defined-signature-without-a-revocation-bit"),
])
def test_a_code_point_the_library_resolves_differently_is_reported(
        tmp_path, source, edit, disagreement):
    """The comparison is only worth having if it notices a difference, so each
    kind is planted in a copy of the library."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    path = lib / source
    text = path.read_text()
    assert text.count(edit[0]) == 1
    path.write_text(text.replace(edit[0], edit[1]))
    document = gen_config.load_config(DEFAULT_CONFIG)
    values = gen_config.resolve_settings(document)
    verdicts, revoke_bits = resolve_every_code_point(tmp_path, default_header(),
                                                     lib_dir=lib)
    assert code_point_disagreements(verdicts, revoke_bits, values) == [disagreement]


# Each table's end row, with the rows before it so the text is unique, and the
# same row given a type the format defines.
END_ROW_TYPES = [
    pytest.param("ECDSA_SIGNATURE_DER, 72u },\n#endif\n    { 0x00u,", "0x06u",
                 id="classical-signatures"),
    pytest.param("OCA_DER_UNDEFINED, 0u },\n#endif\n    { 0x00u,", "0x31u",
                 id="pqc-signatures"),
    pytest.param("HASH_DIGEST_SIZE(32u) },\n#endif\n    { 0x00u,", "0x02u",
                 id="hashes"),
    pytest.param("{ 0x02u, OCA_AES_BLOCK_SIZE },\n#endif\n    { 0x00u,", "0x03u",
                 id="ciphers"),
]


@pytest.mark.parametrize("end_row, planted_type", END_ROW_TYPES)
def test_a_lookup_never_reads_a_tables_end_row(tmp_path, end_row, planted_type):
    """A lookup stops at the table's size as well as at its end row, so a fault
    that makes the end row's type read as non-zero cannot make the walk run
    past the table. Before the size bound, the planted type was found as an
    enabled algorithm, and every other value walked off the end."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    path = lib / "algorithms.c"
    text = path.read_text()
    assert text.count(end_row) == 1
    path.write_text(text.replace(end_row, end_row.replace("0x00u", planted_type)))
    document = gen_config.load_config(DEFAULT_CONFIG)
    values = gen_config.resolve_settings(document)
    verdicts, revoke_bits = resolve_every_code_point(tmp_path, default_header(),
                                                     lib_dir=lib)
    assert code_point_disagreements(verdicts, revoke_bits, values) == []

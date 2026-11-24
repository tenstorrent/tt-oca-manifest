# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The check header, `lib/oca_config_check.h`, and its lock-step with the
generator and the library.

The check header refuses a header the generator would never write: missing a
setting, malformed, in another header format, or combining settings no build
can use. It also refuses the settings' former -D forms. These tests compile
against deliberately broken headers, and hold the check header, the generator
and the library's sources to each other.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

from tt_boot_manifest.oca import constants as oca_constants
from oca_fixtures.generator import (LIB_DIR, CHECK_HEADER, DEFAULT_CONFIG, gen_config,
                                    IMPLEMENTED, SWITCHES, default_header, require_tools)
from oca_fixtures.toolchain import C_COMPILER


# ---------------------------------------------------------------------------
# Lock-step between the generator, the check header and the library
# ---------------------------------------------------------------------------


def _check_header_text():
    with open(CHECK_HEADER) as handle:
        return handle.read()


def test_the_check_header_requires_the_format_the_generator_writes():
    match = re.search(r"#elif OCA_CFG_FORMAT != (\d+)", _check_header_text())
    assert match and int(match.group(1)) == gen_config.CONFIG_FORMAT


@pytest.mark.parametrize("setting", IMPLEMENTED, ids=[s.name for s in IMPLEMENTED])
def test_every_setting_reaches_the_library(setting):
    """A setting nothing reads would be a configuration key with no effect."""
    readers = []
    for name in sorted(os.listdir(LIB_DIR)):
        if name.endswith((".c", ".h")) and name != "oca_config_check.h":
            with open(os.path.join(LIB_DIR, name)) as handle:
                if setting.macro in handle.read():
                    readers.append(name)
    assert readers, f"{setting.macro} is generated but no library source reads it"


def _library_sources():
    for name in sorted(os.listdir(LIB_DIR)):
        if name.endswith((".c", ".h")):
            with open(os.path.join(LIB_DIR, name)) as handle:
                yield name, handle.read()


def test_every_configuration_macro_the_library_reads_is_generated():
    """A misspelled macro in an #if is 0, which would silently turn a feature off."""
    generated = {s.macro for s in IMPLEMENTED} | {
        "OCA_CFG_FORMAT", "OCA_CFG_IS_SWITCH", "OCA_CFG_PORTFOLIO_TEXT",
        "OCA_CFG_PORTFOLIO_DIGEST", "OCA_CFG_PORTFOLIO_ID", "OCA_CFG_PORTFOLIO_SEAL_",
        "OCA_CFG_ID_OF", "OCA_CFG_ID_OF_BYTES", "OCA_CFG_SEAL_PREFIX", "OCA_CFG_SEAL_EXPAND",
        "OCA_CFG_SEAL_PASTE"}
    for name, text in _library_sources():
        for macro in set(re.findall(r"\bOCA_CFG_[A-Z0-9_]+\b", text)):
            assert macro in generated, f"{name} reads {macro}, which nothing generates"


# ---------------------------------------------------------------------------
# The check header, compiled against headers the generator would never write
# ---------------------------------------------------------------------------


PROBE = '#include "oca_validator.h"\nint oca_probe;\n'


def compile_probe(tmp_path, header_text, *defines, lib_dir=LIB_DIR, probe_text=PROBE):
    """Compile a translation unit that includes a header of the library.

    header_text becomes the oca_config.h on the include path; None leaves it
    out entirely. Returns the completed compiler run.
    """
    require_tools(C_COMPILER[0])
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    if header_text is not None:
        (gen / "oca_config.h").write_text(header_text)
    probe = tmp_path / "probe.c"
    probe.write_text(probe_text)
    return subprocess.run(
        [*C_COMPILER, "-std=c99", "-Wall", "-Werror", "-pedantic", "-fsyntax-only",
         "-I", str(lib_dir), "-I", str(gen), *defines, str(probe)],
        capture_output=True, text=True)


def define_pattern(macro):
    """One #define in a generated header, continuation lines included."""
    return re.compile(rf"^#define {macro} (?:.*\\\n)*.*\n", re.M)


def set_define(header, macro, value):
    """Replace one #define's value in a generated header."""
    edited, count = define_pattern(macro).subn(f"#define {macro} {value}\n", header)
    assert count == 1
    return edited


def drop_define(header, macro):
    edited, count = define_pattern(macro).subn("", header)
    assert count == 1
    return edited


SEAL_DEFINE = re.compile(r"^#define OCA_CFG_PORTFOLIO_SEAL_\w+ 1\n", re.M)


def default_settings():
    return gen_config.resolve_settings(gen_config.load_config(DEFAULT_CONFIG))


def restated(header, values, digest):
    """header stating values, digest, the label digest gives, and the seal they
    give, as a hand edit that kept them all in agreement would."""
    for setting in IMPLEMENTED:
        header = set_define(header, setting.macro,
                            gen_config.spelled_value(setting, values[setting.macro]))
    header = set_define(header, "OCA_CFG_PORTFOLIO_DIGEST",
                        ", ".join(f"0x{byte:02x}" for byte in digest))
    header = set_define(header, "OCA_CFG_PORTFOLIO_ID", f"0x{digest[:4].hex()}u")
    header, count = SEAL_DEFINE.subn(
        f"#define {gen_config.portfolio_seal(values, digest)} 1\n", header)
    assert count == 1
    return header


def edit_header(header, drop=(), values=None):
    """A generated header with some #defines removed and others given new values."""
    for macro in drop:
        header = drop_define(header, macro)
    for macro, value in (values or {}).items():
        header = set_define(header, macro, value)
    return header


# A header the generator would never write, and the guard that refuses it.
UNGENERATED_HEADERS = [
    pytest.param({"drop": ["OCA_CFG_FORMAT"]},
                 "oca_config.h was not generated by lib/scripts/gen_config.py",
                 id="no-format"),
    pytest.param({"values": {"OCA_CFG_FORMAT": "2"}},
                 "oca_config.h was generated in another header format",
                 id="other-format"),
    pytest.param({"drop": ["OCA_CFG_PORTFOLIO_ID"]},
                 "oca_config.h is missing OCA_CFG_PORTFOLIO_ID",
                 id="no-portfolio"),
    pytest.param({"drop": ["OCA_CFG_PORTFOLIO_DIGEST"]},
                 "oca_config.h is missing OCA_CFG_PORTFOLIO_DIGEST",
                 id="no-portfolio-digest"),
    pytest.param({"values": {"OCA_CFG_RECHECK_SECURITY_VERSION": "-1"}},
                 "holds a true/false setting that is neither 0 nor 1",
                 id="recheck-not-bool"),
    pytest.param({"values": {"OCA_CFG_VARIANT_CLASSIC": "0", "OCA_CFG_VARIANT_PQC": "0"}},
                 "enables no manifest variant",
                 id="no-variant"),
    pytest.param({"values": {"OCA_CFG_TOC_MAX_IMAGES": "0u"}},
                 "sets toc_max_images below 1",
                 id="toc-zero"),
    pytest.param({"values": {"OCA_CFG_SIG_RSA_3072_PKCS1V15_SHA256": "0",
                             "OCA_CFG_SIG_ECDSA_P256_SHA256": "0",
                             "OCA_CFG_SIG_ML_DSA_87": "0"}},
                 "enables no signature algorithm without [secure_boot] disabled",
                 id="no-signature"),
    pytest.param({"values": {"OCA_CFG_SECURE_BOOT_DISABLED": "1"}},
                 "declares [secure_boot] disabled but enables a signature algorithm",
                 id="secure-boot-disabled-with-a-signature"),
    pytest.param({"values": {"OCA_CFG_SECURE_BOOT_DISABLED": "1",
                             "OCA_CFG_SIG_RSA_3072_PKCS1V15_SHA256": "0",
                             "OCA_CFG_SIG_ECDSA_P256_SHA256": "0",
                             "OCA_CFG_SIG_ML_DSA_87": "0",
                             "OCA_CFG_DER_RSA_PUBLIC_KEY": "0",
                             "OCA_CFG_DER_ECDSA_SIGNATURE": "0"}},
                 "declares [secure_boot] disabled but enables payload encryption",
                 id="secure-boot-disabled-with-encryption"),
    pytest.param({"values": {"OCA_CFG_VARIANT_PQC": "0"}},
                 "enables a PQC signature algorithm without [variants] pqc",
                 id="pqc-signature-without-pqc"),
    pytest.param({"values": {"OCA_CFG_HASH_SHA2_256": "0"}},
                 "enables no hash",
                 id="no-hash"),
    pytest.param({"values": {"OCA_CFG_KDF_SP800_108_HMAC_SHA256": "0"}},
                 "enables only part of payload encryption",
                 id="cipher-without-kdf"),
    pytest.param({"values": {"OCA_CFG_CIPHER_AES_128_CBC": "0",
                             "OCA_CFG_CIPHER_AES_256_CBC": "0"}},
                 "enables only part of payload encryption",
                 id="kdf-without-cipher"),
    pytest.param({"values": {"OCA_CFG_KEY_SOURCE_PRESHARED": "0"}},
                 "enables only part of payload encryption",
                 id="no-key-source"),
]


def test_the_generated_default_compiles(tmp_path):
    result = compile_probe(tmp_path, default_header())
    assert result.returncode == 0, result.stderr


def test_the_library_does_not_compile_without_a_generated_header(tmp_path):
    result = compile_probe(tmp_path, None)
    assert result.returncode != 0
    assert "oca_config.h" in result.stderr


@pytest.mark.parametrize("edits, message", UNGENERATED_HEADERS)
def test_a_header_the_generator_would_not_write_is_refused(tmp_path, edits, message):
    result = compile_probe(tmp_path, edit_header(default_header(), **edits))
    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("setting", SWITCHES, ids=[s.name for s in SWITCHES])
def test_a_switch_neither_0_nor_1_is_refused(tmp_path, setting):
    result = compile_probe(tmp_path, edit_header(default_header(),
                                                 values={setting.macro: "2"}))
    assert result.returncode != 0
    assert "holds a true/false setting that is neither 0 nor 1" in result.stderr


REQUIRING = [setting for setting in IMPLEMENTED if setting.requires]


@pytest.mark.parametrize("setting", REQUIRING, ids=[s.name for s in REQUIRING])
def test_a_header_enabling_a_setting_without_what_it_needs_is_refused(tmp_path, setting):
    """The cases come from the generator's rules, so a setting added there with
    a requirement fails here until the check header refuses it too."""
    needed = {s.macro: "0" for s in IMPLEMENTED if s.name in setting.requires}
    result = compile_probe(tmp_path, edit_header(default_header(), values=needed))
    assert result.returncode != 0
    assert f"enables [{setting.section}] {setting.key} without" in result.stderr


@pytest.mark.parametrize("size, compiles", [
    pytest.param(32, True, id="whole"),
    pytest.param(31, False, id="short"),
    pytest.param(33, False, id="long"),
])
def test_the_library_holds_the_portfolio_digest_to_its_size(tmp_path, size, compiles):
    """An initializer short of the digest would leave its last bytes zero, so
    the build stops unless the header states exactly 32 bytes, even with a
    label and seal that agree with them."""
    values = default_settings()
    stated = bytes([0x5a] * size)
    header = restated(default_header(), values, stated)
    result = compile_probe(tmp_path, header, probe_text='#include "oca_validator.c"\n')
    assert (result.returncode == 0) == compiles, result.stderr


def library_at_version(tmp_path, minor, patch):
    """A copy of the library whose public header states minor and patch."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    header = lib / "oca_validator.h"
    text = header.read_text()
    for part, value in (("MINOR", minor), ("PATCH", patch)):
        text, count = re.subn(rf"^#define OCA_VALIDATOR_VERSION_{part} \S+$",
                              f"#define OCA_VALIDATOR_VERSION_{part} {value}u", text, flags=re.M)
        assert count == 1, part
    header.write_text(text)
    return lib


@pytest.mark.parametrize("minor, patch, fits", [
    pytest.param(255, 255, True, id="both-at-255"),
    pytest.param(256, 0, False, id="minor-256"),
    pytest.param(0, 256, False, id="patch-256"),
])
def test_the_library_holds_each_version_part_to_its_bits(tmp_path, minor, patch, fits):
    """A minor or patch version past 255 would carry into the next part of
    OCA_VALIDATOR_VERSION, so 0.256.0 would read as 1.0.0; the library stops
    the build instead."""
    result = compile_probe(tmp_path, default_header(),
                           lib_dir=library_at_version(tmp_path, minor, patch),
                           probe_text='#include "oca_validator.c"\n')
    assert (result.returncode == 0) == fits, result.stderr
    if not fits:
        assert "oca_validator_version_fits" in result.stderr, result.stderr


SEAL_BROKEN = "oca_config.h states settings its portfolio digest was not computed from"
LABEL_BROKEN = "oca_config.h states a portfolio ID that is not the first 32 bits of its digest"


def another_value(setting, value):
    """A value of setting other than value: a switch flipped, a count halved."""
    return value // 2 if setting.kind == "count" else 1 - value


@pytest.mark.parametrize("setting", IMPLEMENTED, ids=[s.name for s in IMPLEMENTED])
def test_a_setting_edited_by_hand_is_refused(tmp_path, setting):
    """The portfolio the library reports must be the one it builds."""
    values = default_settings()
    edited = gen_config.spelled_value(setting, another_value(setting, values[setting.macro]))
    result = compile_probe(tmp_path, set_define(default_header(), setting.macro, edited))
    assert result.returncode != 0
    assert SEAL_BROKEN in result.stderr, result.stderr


@pytest.mark.parametrize("index", [0, 4, 31])
def test_a_digest_edited_by_hand_is_refused(tmp_path, index):
    """A byte inside the label breaks the label too; any byte breaks the seal."""
    digest = bytearray(gen_config.portfolio_digest(default_settings()))
    digest[index] ^= 0x01
    header = set_define(default_header(), "OCA_CFG_PORTFOLIO_DIGEST",
                        ", ".join(f"0x{byte:02x}" for byte in digest))
    result = compile_probe(tmp_path, header)
    assert result.returncode != 0
    assert SEAL_BROKEN in result.stderr, result.stderr
    assert (LABEL_BROKEN in result.stderr) == (index < 4), result.stderr


def test_a_label_edited_by_hand_is_refused(tmp_path):
    header = set_define(default_header(), "OCA_CFG_PORTFOLIO_ID", "0x00000000u")
    result = compile_probe(tmp_path, header)
    assert result.returncode != 0
    assert LABEL_BROKEN in result.stderr, result.stderr
    assert SEAL_BROKEN not in result.stderr, result.stderr


def test_a_header_without_its_seal_is_refused(tmp_path):
    header, count = SEAL_DEFINE.subn("", default_header())
    assert count == 1
    result = compile_probe(tmp_path, header)
    assert result.returncode != 0
    assert SEAL_BROKEN in result.stderr, result.stderr


def test_a_header_restated_in_agreement_compiles(tmp_path):
    """The seal holds a header's parts to each other, not to the generator: one
    whose settings, digest, label and seal agree compiles, so the checks above
    refuse the edits themselves and not anything that was not generated."""
    values = dict(default_settings(), OCA_CFG_TOC_MAX_IMAGES=16)
    header = restated(default_header(), values, gen_config.portfolio_digest(values))
    result = compile_probe(tmp_path, header, probe_text='#include "oca_validator.c"\n')
    assert result.returncode == 0, result.stderr


def test_the_generated_seal_is_named_for_the_digest_and_every_setting(tmp_path):
    values = default_settings()
    digest = gen_config.portfolio_digest(values)
    seal = gen_config.portfolio_seal(values, digest)
    assert seal.startswith("OCA_CFG_PORTFOLIO_SEAL_" + "".join(f"0x{b:02x}" for b in digest))
    for setting in IMPLEMENTED:
        assert (f"_{setting.macro.removeprefix('OCA_CFG_').lower()}_"
                f"{gen_config.spelled_value(setting, values[setting.macro])}") in seal
    assert f"#define {seal} 1\n" in default_header()


@pytest.mark.parametrize("setting", IMPLEMENTED, ids=[s.name for s in IMPLEMENTED])
def test_a_header_missing_a_setting_is_refused(tmp_path, setting):
    """Named, so a header kept by hand through a library upgrade says which
    setting the upgrade added."""
    result = compile_probe(tmp_path, drop_define(default_header(), setting.macro))
    assert result.returncode != 0
    assert f"oca_config.h is missing {setting.macro}" in result.stderr


@pytest.mark.parametrize("define, key", [
    ("-DOCA_SUPPORT_CLASSIC=0", "[variants] classic / pqc"),
    ("-DOCA_SUPPORT_PQC=0", "[variants] classic / pqc"),
    ("-DOCA_TOC_MAX_IMAGES=32", "[limits] toc_max_images"),
    ("-DOCA_RECHECK_SECURITY_VERSION=0", "[hardening] recheck_security_version"),
])
def test_a_setting_passed_with_minus_d_is_refused_naming_its_key(tmp_path, define, key):
    """A stale override fails loudly instead of being silently ignored."""
    result = compile_probe(tmp_path, default_header(), define)
    assert result.returncode != 0
    assert f"set by {key} in the build configuration file, not with -D" in result.stderr


def library_with_max_digest_size(tmp_path, size):
    """A copy of the library whose largest hash digest is size bytes."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    header = lib / "algorithms.h"
    text, count = re.subn(r"^#define OCA_HASH_MAX_DIGEST_SIZE \S+$",
                          f"#define OCA_HASH_MAX_DIGEST_SIZE {size}u",
                          header.read_text(), flags=re.M)
    assert count == 1
    header.write_text(text)
    return lib


@pytest.mark.parametrize("size, fits", [
    pytest.param(oca_constants.HASH_FIELD_SIZE, True, id="field-width"),
    pytest.param(oca_constants.HASH_FIELD_SIZE + 1, False, id="wider-than-field"),
])
def test_no_hash_digest_may_outgrow_the_hash_fields(tmp_path, size, fits):
    """Every digest is compared within, and padded out to, a fixed-width hash field."""
    lib = library_with_max_digest_size(tmp_path, size)
    result = compile_probe(tmp_path, default_header(), lib_dir=lib,
                           probe_text='#include "algorithms.h"\nint oca_probe;\n')
    if fits:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "OCA_HASH_MAX_DIGEST_SIZE exceeds OCA_LEN_HASH_FIELD" in result.stderr


@pytest.mark.parametrize("size, fits", [
    pytest.param(32, True, id="sha2-256-at-the-maximum"),
    pytest.param(31, False, id="sha2-256-past-the-maximum"),
])
def test_no_hash_row_may_outgrow_the_digest_buffers(tmp_path, size, fits):
    """Every digest buffer is OCA_HASH_MAX_DIGEST_SIZE wide, so a hash row whose
    digest is wider must stop the build rather than overrun one."""
    lib = library_with_max_digest_size(tmp_path, size)
    result = compile_probe(tmp_path, default_header(), lib_dir=lib,
                           probe_text='#include "algorithms.c"\n')
    if fits:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "algorithms.c" in result.stderr

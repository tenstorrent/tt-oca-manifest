# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The validator's generated build configuration.

Three layers, each catching what the others cannot:

- `gen_config.py` turns a TOML configuration into `oca_config.h`, refusing
  anything it cannot describe. Pure Python, no compiler.
- `lib/oca_config_check.h` refuses a header the generator would never write —
  hand-edited, stale, or from another library version — and the settings'
  former -D forms. Exercised by compiling against deliberately broken headers.
- The Makefile regenerates the header on every build, rebuilds when it changes,
  and stops before compiling anything when the configuration is invalid.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

from tt_boot_manifest.oca import constants as oca_constants


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VALIDATOR_DIR = os.path.join(PROJECT_ROOT, "validators", "oca")
LIB_DIR = os.path.join(VALIDATOR_DIR, "lib")
GENERATOR = os.path.join(LIB_DIR, "scripts", "gen_config.py")
CHECK_HEADER = os.path.join(LIB_DIR, "oca_config_check.h")
DEFAULT_CONFIG = os.path.join(LIB_DIR, "oca_config.toml")
BUILD_CONFIG_DIR = os.path.join(VALIDATOR_DIR, "test", "build_configs")

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"


def _load(path, name):
    """Import a standalone script by path; it is not on any package path.

    Registered in sys.modules before it runs, because a dataclass looks its own
    module up there while it is being defined.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen_config = _load(GENERATOR, "oca_gen_config")
REQUIRED = [setting for setting in gen_config.SETTINGS if setting.required]
IMPLEMENTED = [setting for setting in gen_config.SETTINGS if setting.implemented]
SWITCHES = [setting for setting in IMPLEMENTED if setting.kind == "bool"]
NOT_IMPLEMENTED = [setting for setting in gen_config.SETTINGS if not setting.implemented]

DEFAULT_VALUES = {
    "OCA_CFG_VARIANT_CLASSIC": 1,
    "OCA_CFG_VARIANT_PQC": 1,
    "OCA_CFG_TOC_MAX_IMAGES": 256,
    "OCA_CFG_RECHECK_SECURITY_VERSION": 1,
    "OCA_CFG_HASH_SHA2_256": 1,
    "OCA_CFG_SIG_RSA_3072_PKCS1V15_SHA256": 1,
    "OCA_CFG_SIG_ECDSA_P256_SHA256": 1,
    "OCA_CFG_SIG_ML_DSA_87": 1,
    "OCA_CFG_DER_RSA_PUBLIC_KEY": 1,
    "OCA_CFG_DER_ECDSA_SIGNATURE": 1,
    "OCA_CFG_CIPHER_AES_128_CBC": 1,
    "OCA_CFG_CIPHER_AES_256_CBC": 1,
    "OCA_CFG_KDF_SP800_108_HMAC_SHA256": 1,
    "OCA_CFG_KEY_SOURCE_PRESHARED": 1,
}


def config_text(classic="true", pqc="true", toc_max_images="256",
                recheck_security_version="true", sha2_256="true", rsa="true", ecdsa="true",
                ml_dsa_87="true", der_rsa="true", der_ecdsa="true",
                aes_128="true", aes_256="true", kdf="true", preshared="true",
                extra=""):
    """A complete configuration, every value given as its TOML text."""
    return (
        "[variants]\n"
        f"classic = {classic}\n"
        f"pqc = {pqc}\n"
        "\n[limits]\n"
        f"toc_max_images = {toc_max_images}\n"
        "\n[hardening]\n"
        f"recheck_security_version = {recheck_security_version}\n"
        "\n[hash]\n"
        f"sha2_256 = {sha2_256}\n"
        "\n[signature_classic]\n"
        f"rsa_3072_pkcs1v15_sha256 = {rsa}\n"
        f"ecdsa_p256_sha256 = {ecdsa}\n"
        "\n[signature_pqc]\n"
        f"ml_dsa_87 = {ml_dsa_87}\n"
        "\n[der]\n"
        f"rsa_public_key = {der_rsa}\n"
        f"ecdsa_signature = {der_ecdsa}\n"
        "\n[encryption_cipher]\n"
        f"aes_128_cbc = {aes_128}\n"
        f"aes_256_cbc = {aes_256}\n"
        "\n[encryption_kdf]\n"
        f"sp800_108_hmac_sha256 = {kdf}\n"
        "\n[encryption_key_source]\n"
        f"preshared = {preshared}\n"
        "\n[encryption_kem]\n"
        f"{extra}"
    )


def write_config(directory, text, name="board.toml"):
    path = directory / name
    path.write_text(text)
    return str(path)


def problems_for(text):
    """The generator's complaints about a configuration, or [] when it accepts it."""
    try:
        gen_config.resolve_settings(gen_config.tomllib.loads(text))
    except gen_config.ConfigError as exc:
        return exc.problems
    return []


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


# ---------------------------------------------------------------------------
# The generator
# ---------------------------------------------------------------------------


def test_the_shipped_default_is_the_documented_default():
    document, _ = gen_config.load_config(DEFAULT_CONFIG)
    assert gen_config.resolve_settings(document) == DEFAULT_VALUES


@pytest.mark.parametrize("name, changes", [
    # A Classic-only build carries no PQC signature, so ML-DSA-87 goes too.
    ("classic_only.toml", {"OCA_CFG_VARIANT_PQC": 0, "OCA_CFG_SIG_ML_DSA_87": 0}),
    ("pqc_only.toml", {"OCA_CFG_VARIANT_CLASSIC": 0}),
])
def test_the_variant_build_configs_differ_from_the_default_only_in_variants(
        name, changes):
    document, _ = gen_config.load_config(os.path.join(BUILD_CONFIG_DIR, name))
    assert gen_config.resolve_settings(document) == {**DEFAULT_VALUES, **changes}


def test_a_complete_configuration_is_accepted():
    assert problems_for(config_text()) == []


@pytest.mark.parametrize("setting", REQUIRED, ids=[s.name for s in REQUIRED])
def test_every_setting_is_required(setting):
    """A configuration replaces the default, so leaving a setting out is refused,
    never filled in from a default nobody reviewed."""
    text = "".join(line + "\n" for line in config_text().splitlines()
                   if not line.startswith(f"{setting.key} ="))
    assert problems_for(text) == [
        f"{setting.name} is required: a configuration replaces the default, "
        f"so every setting must be stated"]


def test_an_empty_configuration_names_every_setting():
    """Every required setting, and that no hash or signature algorithm is enabled."""
    assert len(problems_for("")) == len(REQUIRED) + 2


def test_an_unknown_section_is_refused():
    assert problems_for(config_text(extra="\n[signing]\nrsa = true\n")) == [
        "unknown section [signing]"]


def test_an_unknown_key_is_refused():
    """A misspelled setting is refused, not ignored while its intended value is
    silently missing."""
    text = config_text().replace("pqc = true", "pqc = true\npcq = false")
    assert problems_for(text) == ["unknown key variants.pcq"]


def test_a_section_that_is_not_a_table_is_refused():
    text = config_text().replace("[limits]\ntoc_max_images = 256\n", "")
    text = "limits = 256\n" + text
    assert "[limits] must be a table" in problems_for(text)


@pytest.mark.parametrize("value", ["1", "0", '"true"', "[]"])
def test_a_true_false_setting_takes_only_true_or_false(value):
    assert problems_for(config_text(classic=value)) == [
        f"variants.classic must be true or false, not "
        f"{gen_config.tomllib.loads('v = ' + value)['v']!r}"]


@pytest.mark.parametrize("value", ["true", '"256"', "256.0"])
def test_a_count_takes_only_an_integer(value):
    problems = problems_for(config_text(toc_max_images=value))
    assert len(problems) == 1
    assert problems[0].startswith("limits.toc_max_images must be an integer")


@pytest.mark.parametrize("value", ["0", "-1", str(2**32)])
def test_a_count_outside_its_range_is_refused(value):
    assert problems_for(config_text(toc_max_images=value)) == [
        f"limits.toc_max_images must be between 1 and {2**32 - 1}, not {value}"]


@pytest.mark.parametrize("value", ["1", str(2**32 - 1)])
def test_a_count_at_either_end_of_its_range_is_accepted(value):
    assert problems_for(config_text(toc_max_images=value)) == []


def test_a_build_that_accepts_no_variant_is_refused():
    assert problems_for(config_text(classic="false", pqc="false", ml_dsa_87="false")) == [
        "[variants] must enable at least one of classic and pqc"]


# ---------------------------------------------------------------------------
# The algorithm portfolio
# ---------------------------------------------------------------------------


def test_an_algorithm_left_out_is_off():
    """An adopter's file names what it accepts; an algorithm it does not name is
    refused, never inherited from the default."""
    text = config_text().replace("ecdsa_p256_sha256 = true\n", "")
    text = text.replace("ecdsa_signature = true", "ecdsa_signature = false")
    values = gen_config.resolve_settings(gen_config.tomllib.loads(text))
    assert values["OCA_CFG_SIG_ECDSA_P256_SHA256"] == 0


def test_an_algorithm_section_may_be_left_out_entirely():
    text = config_text(ml_dsa_87="false").replace("\n[signature_pqc]\nml_dsa_87 = false\n", "")
    values = gen_config.resolve_settings(gen_config.tomllib.loads(text))
    assert values["OCA_CFG_SIG_ML_DSA_87"] == 0


@pytest.mark.parametrize("setting", NOT_IMPLEMENTED, ids=[s.name for s in NOT_IMPLEMENTED])
def test_an_algorithm_the_library_has_no_rules_for_cannot_be_turned_on(setting):
    """Turning one on is a build error, never a request quietly ignored."""
    text = config_text().replace(f"[{setting.section}]\n",
                                 f"[{setting.section}]\n{setting.key} = true\n", 1)
    assert problems_for(text) == [
        f"{setting.name} ({setting.description}) is not implemented in this "
        f"library; implement its rules before enabling it"]


@pytest.mark.parametrize("setting", NOT_IMPLEMENTED, ids=[s.name for s in NOT_IMPLEMENTED])
def test_an_algorithm_the_library_has_no_rules_for_may_be_stated_off(setting):
    text = config_text().replace(f"[{setting.section}]\n", f"[{setting.section}]\n"
                                 f"{setting.key} = false\n", 1)
    assert problems_for(text) == []


def test_every_algorithm_is_listed_by_its_format_code():
    """Each class lists the format's algorithms once each, so a configuration can
    name every one."""
    for group in (gen_config.HASHES, gen_config.CLASSICAL_SIGNATURES,
                  gen_config.PQC_SIGNATURES,
                  gen_config.CIPHERS, gen_config.KDFS, gen_config.KEY_SOURCES,
                  gen_config.KEMS):
        codes = [setting.code for setting in group]
        assert len(codes) == len(set(codes))
    assert {s.code for s in gen_config.CLASSICAL_SIGNATURES} == {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x0B}
    assert {s.code for s in gen_config.PQC_SIGNATURES} == {
        0x31, 0x32, 0x33, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56}
    assert {s.code for s in gen_config.HASHES} == set(range(0x01, 0x09))
    assert {s.code for s in gen_config.CIPHERS} == {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12}
    assert {s.code for s in gen_config.KDFS} == set(range(0x0000, 0x0009))
    assert {s.code for s in gen_config.KEY_SOURCES} == {0x1, 0x2}
    assert {s.code for s in gen_config.KEMS} == {
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0101, 0x0102}


def test_a_build_with_no_hash_is_refused():
    assert problems_for(config_text(sha2_256="false")) == [
        "no hash is enabled: [hash] must enable at least one, since every "
        "manifest carries a manifest_hash"]


def test_a_build_with_no_signature_algorithm_is_refused():
    text = config_text(rsa="false", ecdsa="false", ml_dsa_87="false",
                       der_rsa="false", der_ecdsa="false")
    assert problems_for(text) == [
        "no signature algorithm is enabled: [signature_classic] or "
        "[signature_pqc] must enable at least one"]


def test_one_signature_algorithm_is_enough():
    text = config_text(rsa="false", ecdsa="false", der_rsa="false", der_ecdsa="false")
    assert problems_for(text) == []


def test_a_pqc_signature_needs_the_pqc_variant():
    assert problems_for(config_text(pqc="false")) == [
        "signature_pqc.ml_dsa_87 needs [variants] pqc, the only variant that "
        "carries a PQC signature"]


@pytest.mark.parametrize("changes, problem", [
    ({"rsa": "false"},
     "der.rsa_public_key needs one of signature_classic.rsa_3072_pkcs1v15_sha256, "
     "signature_classic.rsa_3072_pss_sha256, signature_classic.rsa_4096_pkcs1v15_sha512, "
     "signature_classic.rsa_4096_pss_sha512 enabled"),
    ({"ecdsa": "false"},
     "der.ecdsa_signature needs one of signature_classic.ecdsa_p256_sha256, "
     "signature_classic.ecdsa_p384_sha384, signature_classic.ecdsa_p521_sha512 enabled"),
], ids=["rsa", "ecdsa"])
def test_a_der_encoding_needs_an_algorithm_of_its_family(changes, problem):
    assert problems_for(config_text(**changes)) == [problem]


@pytest.mark.parametrize("der_rsa, der_ecdsa", [("false", "true"), ("true", "false"),
                                                ("false", "false")])
def test_each_der_encoding_can_be_turned_off_on_its_own(der_rsa, der_ecdsa):
    text = config_text(der_rsa=der_rsa, der_ecdsa=der_ecdsa)
    values = gen_config.resolve_settings(gen_config.tomllib.loads(text))
    assert values["OCA_CFG_DER_RSA_PUBLIC_KEY"] == (der_rsa == "true")
    assert values["OCA_CFG_DER_ECDSA_SIGNATURE"] == (der_ecdsa == "true")


def test_a_build_may_turn_payload_encryption_off():
    """Every encrypted payload is then refused; signed cleartext still boots."""
    text = config_text(aes_128="false", aes_256="false", kdf="false", preshared="false")
    assert problems_for(text) == []


@pytest.mark.parametrize("changes, empty", [
    ({"kdf": "false"}, "[encryption_kdf]"),
    ({"preshared": "false"}, "[encryption_key_source]"),
    ({"aes_128": "false", "aes_256": "false"}, "[encryption_cipher]"),
    ({"aes_128": "false", "aes_256": "false", "kdf": "false"}, "[encryption_cipher]"),
], ids=["no-kdf", "no-key-source", "no-cipher", "key-source-alone"])
def test_payload_encryption_is_enabled_whole_or_not_at_all(changes, empty):
    problems = problems_for(config_text(**changes))
    assert problems and all("enable a cipher, a KDF and a key source together, "
                            "or none of them" in p for p in problems)
    assert any(p.startswith(f"{empty} enables nothing") for p in problems)


def test_one_cipher_is_enough():
    assert problems_for(config_text(aes_128="false")) == []


def test_an_unimplemented_algorithm_generates_no_macro(tmp_path):
    header = gen_config.header_for_config(write_config(tmp_path, config_text()))
    for setting in NOT_IMPLEMENTED:
        assert setting.key.upper() not in header


def test_every_problem_is_reported_at_once():
    problems = problems_for(config_text(classic="1", toc_max_images="0",
                                        extra="\n[extra]\n"))
    assert problems == [
        "unknown section [extra]",
        "variants.classic must be true or false, not 1",
        f"limits.toc_max_images must be between 1 and {2**32 - 1}, not 0",
    ]


@pytest.mark.parametrize("content, message", [
    (b"[variants\n", "is not valid TOML"),
    (b"\xff\xfe[variants]\n", "is not UTF-8 text"),
])
def test_an_unparseable_file_is_refused(tmp_path, content, message):
    path = tmp_path / "board.toml"
    path.write_bytes(content)
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.load_config(str(path))
    assert message in caught.value.problems[0]


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.load_config(str(tmp_path / "absent.toml"))
    assert caught.value.problems[0].startswith("cannot read ")


def test_an_invalid_configuration_raises_before_writing(tmp_path):
    config = write_config(tmp_path, config_text(pqc="2"))
    out = tmp_path / "gen" / "oca_config.h"
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.generate(config, str(out))
    assert caught.value.problems == ["variants.pqc must be true or false, not 2"]
    assert not out.exists()


def test_the_header_holds_every_setting_and_its_source_digest(tmp_path):
    config = write_config(tmp_path, config_text(toc_max_images="32"))
    header = gen_config.header_for_config(config)
    assert "#define OCA_CFG_FORMAT 1\n" in header
    assert "#define OCA_CFG_TOC_MAX_IMAGES 32u\n" in header
    assert "#define OCA_CFG_VARIANT_CLASSIC 1\n" in header
    digest = gen_config.hashlib.sha256((tmp_path / "board.toml").read_bytes())
    assert digest.hexdigest() in header


def test_the_header_depends_only_on_the_configuration(tmp_path):
    """The same file in two directories yields the same header, byte for byte, so a
    committed header does not change with whoever generated it."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = write_config(tmp_path / "a", config_text())
    second = write_config(tmp_path / "b", config_text())
    assert gen_config.header_for_config(first) == gen_config.header_for_config(second)


def test_generate_creates_the_header_and_its_directory(tmp_path):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "gen" / "nested" / "oca_config.h"
    assert gen_config.generate(config, str(out)) is True
    assert out.read_text() == gen_config.header_for_config(config)


def test_an_unchanged_header_is_not_rewritten(tmp_path):
    """Leaving the file alone keeps its timestamp, which keeps a build incremental."""
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    assert gen_config.generate(config, str(out)) is True
    os.utime(out, (1_000_000_000, 1_000_000_000))
    assert gen_config.generate(config, str(out)) is False
    assert out.stat().st_mtime == 1_000_000_000


def test_a_changed_configuration_rewrites_the_header(tmp_path):
    out = tmp_path / "oca_config.h"
    gen_config.generate(write_config(tmp_path, config_text()), str(out))
    changed = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    assert gen_config.generate(changed, str(out)) is True
    assert "#define OCA_CFG_VARIANT_PQC 0\n" in out.read_text()


def test_a_header_is_current_only_when_it_matches_exactly(tmp_path):
    out = tmp_path / "oca_config.h"
    text = gen_config.header_for_config(write_config(tmp_path, config_text()))
    assert gen_config.header_is_current(str(out), text) is False
    out.write_text(text)
    assert gen_config.header_is_current(str(out), text) is True
    out.write_text(text + "\n")
    assert gen_config.header_is_current(str(out), text) is False


# The command line is what the Makefile and an adopter's build run, so its exit
# codes and messages are part of the contract. Called in-process.


def test_the_command_line_writes_and_reports_only_on_change(tmp_path, capsys):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    assert gen_config.main(["--config", config, "--out", str(out)]) == 0
    assert capsys.readouterr().out == f"gen_config: wrote {out} from {config}\n"
    assert gen_config.main(["--config", config, "--out", str(out)]) == 0
    assert capsys.readouterr().out == ""


def test_the_command_line_exits_2_naming_every_problem(tmp_path, capsys):
    config = write_config(tmp_path, config_text(classic="1", pqc="2"))
    out = tmp_path / "oca_config.h"
    assert gen_config.main(["--config", config, "--out", str(out)]) == 2
    assert not out.exists()
    assert capsys.readouterr().err.splitlines() == [
        f"gen_config: {config}: variants.classic must be true or false, not 1",
        f"gen_config: {config}: variants.pqc must be true or false, not 2",
    ]


def test_check_accepts_a_current_header(tmp_path):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    gen_config.generate(config, str(out))
    assert gen_config.main(["--config", config, "--out", str(out), "--check"]) == 0


def test_check_refuses_a_stale_header_without_touching_it(tmp_path, capsys):
    out = tmp_path / "oca_config.h"
    gen_config.generate(write_config(tmp_path, config_text()), str(out))
    before = out.read_bytes()
    config = write_config(tmp_path, config_text(toc_max_images="8"))
    assert gen_config.main(["--config", config, "--out", str(out), "--check"]) == 1
    assert out.read_bytes() == before
    assert "is missing or stale" in capsys.readouterr().err


def test_check_refuses_a_missing_header_without_creating_it(tmp_path):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    assert gen_config.main(["--config", config, "--out", str(out), "--check"]) == 1
    assert not out.exists()


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
def test_the_check_header_requires_every_setting(setting):
    guard = re.search(r"#if (!defined\(OCA_CFG_VARIANT_CLASSIC\).*?)\n#error",
                      _check_header_text(), re.S)
    assert guard and f"!defined({setting.macro})" in guard.group(1)


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


@pytest.mark.parametrize("setting", SWITCHES, ids=[s.name for s in SWITCHES])
def test_the_check_header_holds_every_switch_to_0_or_1(setting):
    assert f"!OCA_CFG_IS_SWITCH({setting.macro})" in _check_header_text()


def _library_sources():
    for name in sorted(os.listdir(LIB_DIR)):
        if name.endswith((".c", ".h")):
            with open(os.path.join(LIB_DIR, name)) as handle:
                yield name, handle.read()


def test_every_configuration_macro_the_library_reads_is_generated():
    """A misspelled macro in an #if is 0, which would silently turn a feature off."""
    generated = {s.macro for s in IMPLEMENTED} | {"OCA_CFG_FORMAT", "OCA_CFG_IS_SWITCH"}
    for name, text in _library_sources():
        for macro in set(re.findall(r"\bOCA_CFG_[A-Z0-9_]+\b", text)):
            assert macro in generated, f"{name} reads {macro}, which nothing generates"


def _table_rows():
    """{macro: format code} for every algorithm algorithms.c compiles in under a
    configuration macro: a table row, or a value a status function accepts."""
    with open(os.path.join(LIB_DIR, "algorithms.c")) as handle:
        text = handle.read()
    rows = re.findall(r"#if (OCA_CFG_(?:HASH|SIG|CIPHER)_\w+)\n(?:\s*/\*.*?\*/\n)?"
                      r"\s*\{ (0x[0-9A-Fa-f]+)u,", text, re.S)
    accepted = re.findall(r"#if (OCA_CFG_(?:KDF|KEY_SOURCE)_\w+)\n"
                          r"\s*if \(\w+ == (0x[0-9A-Fa-f]+)u\)", text)
    return {macro: int(code, 16) for macro, code in rows + accepted}


def test_every_implemented_algorithm_has_a_table_row_with_its_code():
    algorithms = {s.macro: s.code for s in IMPLEMENTED if s.code is not None}
    assert _table_rows() == algorithms


def test_every_algorithm_the_packer_writes_is_enabled_by_default():
    """The producer can never emit a signature the default validator refuses."""
    document, _ = gen_config.load_config(DEFAULT_CONFIG)
    values = gen_config.resolve_settings(document)
    by_code = {
        "signature_classic": oca_constants.CLASSIC_SIGNING_TYPES,
        "signature_pqc": oca_constants.PQC_SIGNING_TYPES,
    }
    by_code["hash"] = {hash_type.value for hash_type in oca_constants.OcaClassicHashType}
    by_code["encryption_cipher"] = oca_constants.ENCRYPTION_TYPES_SUPPORTED
    by_code["encryption_kdf"] = {kdf.value for kdf in oca_constants.OcaEncryptionKdf}
    by_code["encryption_key_source"] = {oca_constants.ENCRYPTION_INPUT_KEY_SOURCE_PRESHARED}
    for section, codes in by_code.items():
        for code in codes:
            setting = next(s for s in gen_config.SETTINGS
                           if s.section == section and s.code == code)
            assert setting.implemented and values[setting.macro] == 1, setting.name
    # The packer writes DER RSA keys and DER ECDSA signatures.
    assert values["OCA_CFG_DER_RSA_PUBLIC_KEY"] == 1
    assert values["OCA_CFG_DER_ECDSA_SIGNATURE"] == 1


# ---------------------------------------------------------------------------
# The check header, compiled against headers the generator would never write
# ---------------------------------------------------------------------------


PROBE = '#include "oca_validator.h"\nint oca_probe;\n'


def compile_probe(tmp_path, header_text, *defines, lib_dir=LIB_DIR, probe_text=PROBE):
    """Compile a translation unit that includes a header of the library.

    header_text becomes the oca_config.h on the include path; None leaves it
    out entirely. Returns the completed compiler run.
    """
    require_tools("cc")
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    if header_text is not None:
        (gen / "oca_config.h").write_text(header_text)
    probe = tmp_path / "probe.c"
    probe.write_text(probe_text)
    return subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Werror", "-pedantic", "-fsyntax-only",
         "-I", str(lib_dir), "-I", str(gen), *defines, str(probe)],
        capture_output=True, text=True)


def default_header():
    return gen_config.header_for_config(DEFAULT_CONFIG)


def set_define(header, macro, value):
    """Replace one #define's value in a generated header."""
    edited, count = re.subn(rf"^#define {macro} .*$", f"#define {macro} {value}",
                            header, flags=re.M)
    assert count == 1
    return edited


def drop_define(header, macro):
    edited, count = re.subn(rf"^#define {macro} .*\n", "", header, flags=re.M)
    assert count == 1
    return edited


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
                 "oca_config.h was generated for another version of this library",
                 id="other-format"),
    pytest.param({"values": {"OCA_CFG_VARIANT_PQC": "2"}},
                 "holds a true/false setting that is neither 0 nor 1",
                 id="variant-not-bool"),
    pytest.param({"values": {"OCA_CFG_RECHECK_SECURITY_VERSION": "-1"}},
                 "holds a true/false setting that is neither 0 nor 1",
                 id="recheck-not-bool"),
    pytest.param({"values": {"OCA_CFG_VARIANT_CLASSIC": "0", "OCA_CFG_VARIANT_PQC": "0"}},
                 "enables no manifest variant",
                 id="no-variant"),
    pytest.param({"values": {"OCA_CFG_TOC_MAX_IMAGES": "0u"}},
                 "sets toc_max_images below 1",
                 id="toc-zero"),
    pytest.param({"values": {"OCA_CFG_DER_ECDSA_SIGNATURE": "2"}},
                 "holds a true/false setting that is neither 0 nor 1",
                 id="der-not-bool"),
    pytest.param({"values": {"OCA_CFG_SIG_RSA_3072_PKCS1V15_SHA256": "0",
                             "OCA_CFG_SIG_ECDSA_P256_SHA256": "0",
                             "OCA_CFG_SIG_ML_DSA_87": "0"}},
                 "enables no signature algorithm",
                 id="no-signature"),
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


@pytest.mark.parametrize("setting", IMPLEMENTED, ids=[s.name for s in IMPLEMENTED])
def test_a_header_missing_a_setting_is_refused(tmp_path, setting):
    result = compile_probe(tmp_path, drop_define(default_header(), setting.macro))
    assert result.returncode != 0
    assert "oca_config.h is missing a setting" in result.stderr


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
    """A copy of the library's headers whose largest hash digest is size bytes."""
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts", "*.c"))
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


# ---------------------------------------------------------------------------
# The Makefile
# ---------------------------------------------------------------------------


def run_make(build_dir, *args):
    require_tools("make", "cc")
    return subprocess.run(
        ["make", "-C", VALIDATOR_DIR, f"BUILD={build_dir}", *args],
        capture_output=True, text=True,
        env={**os.environ, "PYTHON": sys.executable})


def test_an_invalid_configuration_stops_the_build_before_any_compile(tmp_path):
    config = write_config(tmp_path, config_text(toc_max_images="0"))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "lib")
    assert result.returncode != 0
    assert "limits.toc_max_images must be between 1" in result.stderr
    assert not list((tmp_path / "build").rglob("*.o"))


def test_a_changed_configuration_rebuilds_and_an_unchanged_one_does_not(tmp_path):
    build = tmp_path / "build"
    config = write_config(tmp_path, config_text())
    assert run_make(build, f"CONFIG={config}", "lib").returncode == 0
    variant_object = build / "lib" / "oca_variant.o"
    first = variant_object.stat().st_mtime_ns

    unchanged = run_make(build, f"CONFIG={config}", "lib")
    assert unchanged.returncode == 0
    assert variant_object.stat().st_mtime_ns == first, unchanged.stdout

    # make 3.81 compares timestamps to the whole second, so a header rewritten
    # in the same second as the objects would not look newer than them.
    time.sleep(1.1)
    write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    changed = run_make(build, f"CONFIG={config}", "lib")
    assert changed.returncode == 0
    assert variant_object.stat().st_mtime_ns != first, changed.stdout
    assert "#define OCA_CFG_VARIANT_PQC 0" in (build / "gen" / "oca_config.h").read_text()


def test_the_unit_tests_pass_under_a_reduced_configuration(tmp_path):
    """The unit tests read every setting through its macro, so none of them
    depends on a default. Turning the recheck off also runs the branch of the
    suite that only exists without it."""
    config = write_config(tmp_path, config_text(
        toc_max_images="16", recheck_security_version="false"))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "unit_test")
    assert result.returncode == 0, result.stdout + result.stderr
    # The driver reports on stderr.
    summary = re.search(r"^(\d+)/(\d+) passed$", result.stderr, re.M)
    assert summary and summary.group(1) == summary.group(2), result.stderr
    assert "PASS: test_anti_rollback_evaluated_once_when_recheck_disabled" in result.stderr

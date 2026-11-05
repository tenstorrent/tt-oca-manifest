# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The validator's generated build configuration.

Three layers, each catching what the others cannot:

- `gen_config.py` turns a TOML configuration into `oca_config.h`, refusing
  anything it cannot describe. Pure Python, no compiler.
- `lib/oca_config_check.h` refuses a header the generator would never write —
  missing a setting, malformed, or from another library version — and the
  settings' former -D forms. Exercised by compiling against deliberately
  broken headers.
- The Makefile regenerates the header on every build, rebuilds when it changes,
  and stops before compiling anything when the configuration is invalid.
"""

from __future__ import annotations

import builtins
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

from tt_boot_manifest.oca import constants as oca_constants
from oca_fixtures import build_config


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

# Each implemented setting's default, as the README's Settings table documents
# it. A setting the table leaves out has none, which the default's own test
# reports.
DOCUMENTED = build_config.documented_defaults()
DEFAULT_VALUES = {s.macro: DOCUMENTED[s.name] for s in IMPLEMENTED if s.name in DOCUMENTED}

# The settings these tests change most, by the short names their calls use.
SHORT_NAMES = {
    "classic": "variants.classic",
    "pqc": "variants.pqc",
    "toc_max_images": "limits.toc_max_images",
    "recheck_security_version": "hardening.recheck_security_version",
    "secure_boot_disabled": "secure_boot.disabled",
    "sha2_256": "hash.sha2_256",
    "rsa": "signature_classic.rsa_3072_pkcs1v15_sha256",
    "ecdsa": "signature_classic.ecdsa_p256_sha256",
    "ml_dsa_87": "signature_pqc.ml_dsa_87",
    "der_rsa": "der.rsa_public_key",
    "der_ecdsa": "der.ecdsa_signature",
    "aes_128": "encryption_cipher.aes_128_cbc",
    "aes_256": "encryption_cipher.aes_256_cbc",
    "kdf": "encryption_kdf.sp800_108_hmac_sha256",
    "preshared": "encryption_key_source.preshared",
}


def config_text(extra="", **changes):
    """A complete configuration: the shipped default, with each change named by
    its short name and given as its TOML text."""
    return build_config.config_text(
        {SHORT_NAMES[name]: value for name, value in changes.items()}, extra)


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


def test_the_readme_documents_every_setting():
    """The Settings table is where the tests read each default from, so a
    setting it leaves out is reported here rather than skipped."""
    assert set(DOCUMENTED) == {s.name for s in IMPLEMENTED}


def test_the_shipped_default_is_the_documented_default():
    document = gen_config.load_config(DEFAULT_CONFIG)
    assert gen_config.resolve_settings(document) == DEFAULT_VALUES


@pytest.mark.parametrize("name, changes", [
    # A Classic-only build carries no PQC signature, so ML-DSA-87 goes too.
    ("classic_only.toml", {"OCA_CFG_VARIANT_PQC": 0, "OCA_CFG_SIG_ML_DSA_87": 0}),
    ("pqc_only.toml", {"OCA_CFG_VARIANT_CLASSIC": 0}),
])
def test_the_variant_build_configs_differ_from_the_default_only_as_their_variants_need(
        name, changes):
    document = gen_config.load_config(os.path.join(BUILD_CONFIG_DIR, name))
    assert gen_config.resolve_settings(document) == {**DEFAULT_VALUES, **changes}


# Verifies nothing: every signature algorithm, DER encoding and payload
# encryption setting off, as the declaration requires.
NO_SECURE_BOOT = {"rsa": "false", "ecdsa": "false", "ml_dsa_87": "false",
                  "der_rsa": "false", "der_ecdsa": "false", "aes_128": "false",
                  "aes_256": "false", "kdf": "false", "preshared": "false"}


def test_the_hash_only_build_config_verifies_nothing():
    document = gen_config.load_config(os.path.join(BUILD_CONFIG_DIR, "hash_only.toml"))
    algorithms = {macro: 0 for macro in DEFAULT_VALUES
                  if macro.startswith(("OCA_CFG_SIG_", "OCA_CFG_DER_", "OCA_CFG_CIPHER_",
                                       "OCA_CFG_KDF_", "OCA_CFG_KEY_SOURCE_"))}
    assert gen_config.resolve_settings(document) == {
        **DEFAULT_VALUES, **algorithms, "OCA_CFG_SECURE_BOOT_DISABLED": 1}


def test_a_complete_configuration_is_accepted():
    assert problems_for(config_text()) == []


@pytest.mark.parametrize("setting", REQUIRED, ids=[s.name for s in REQUIRED])
def test_a_required_setting_left_out_is_refused(setting):
    """A configuration replaces the default, so leaving a required setting out
    is refused, never filled in from a default nobody reviewed."""
    text = "".join(line + "\n" for line in config_text().splitlines()
                   if not line.startswith(f"{setting.key} ="))
    assert problems_for(text) == [
        f"{setting.name} is required: a configuration replaces the default, "
        f"so it must state every required setting"]


def test_only_algorithms_encodings_and_declarations_are_optional():
    """A setting left out of a configuration is off. That is safe only for one
    whose absence keeps what every existing configuration builds; anything else
    must be required, so an upgrade adding it stops the build until the adopter
    chooses. Setting's docstring states the rule."""
    for setting in gen_config.SETTINGS:
        if not setting.required:
            assert (setting.code is not None or setting.requires
                    or setting.macro in DECLARATIONS), setting.name


def test_an_empty_configuration_names_every_required_setting():
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
    text = build_config.config_text({setting.name: True})
    assert problems_for(text) == [
        f"{setting.name} ({setting.description}) is not implemented in this "
        f"library; implement its rules before enabling it"]


@pytest.mark.parametrize("setting", NOT_IMPLEMENTED, ids=[s.name for s in NOT_IMPLEMENTED])
def test_an_algorithm_the_library_has_no_rules_for_may_be_stated_off(setting):
    assert problems_for(build_config.config_text({setting.name: False})) == []


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


@pytest.mark.parametrize("declaration", [None, "false"])
def test_a_build_with_no_signature_algorithm_must_declare_secure_boot_disabled(
        declaration):
    """A build that cannot verify a signature is allowed, but only by saying so:
    leaving every algorithm out is otherwise a mistake."""
    text = config_text(**NO_SECURE_BOOT, secure_boot_disabled=declaration)
    assert problems_for(text) == [
        "no signature algorithm is enabled: enable one in [signature_classic] or "
        "[signature_pqc], or declare a build without secure boot with "
        "[secure_boot] disabled = true"]


def test_a_build_that_declares_secure_boot_disabled_needs_only_a_hash():
    assert problems_for(config_text(**NO_SECURE_BOOT, secure_boot_disabled="true")) == []


@pytest.mark.parametrize("enabled, named", [
    pytest.param({"ecdsa": "true"},
                 "signature_classic.ecdsa_p256_sha256 enables one; turn it",
                 id="one"),
    pytest.param({"rsa": "true", "ecdsa": "true"},
                 "signature_classic.rsa_3072_pkcs1v15_sha256, "
                 "signature_classic.ecdsa_p256_sha256 enable them; turn them",
                 id="two"),
])
def test_a_build_that_declares_secure_boot_disabled_verifies_no_signature(enabled, named):
    text = config_text(**{**NO_SECURE_BOOT, **enabled}, secure_boot_disabled="true")
    assert problems_for(text) == [
        "[secure_boot] disabled = true declares a build that verifies no "
        f"signature, but {named} off or remove the declaration"]


def test_a_build_that_declares_secure_boot_disabled_decrypts_nothing():
    """A payload is decrypted only once its manifest's signature verifies, so a
    cipher in a build that verifies none could never be used."""
    text = config_text(**{**NO_SECURE_BOOT, "aes_256": "true", "kdf": "true",
                          "preshared": "true"}, secure_boot_disabled="true")
    assert problems_for(text) == [
        "[secure_boot] disabled = true refuses every encrypted payload, which is "
        "decrypted only once its manifest's signature verifies, but "
        "encryption_cipher.aes_256_cbc, encryption_kdf.sp800_108_hmac_sha256, "
        "encryption_key_source.preshared enable payload encryption; turn them off"]


def test_one_signature_algorithm_is_enough():
    text = config_text(rsa="false", ecdsa="false", der_rsa="false", der_ecdsa="false")
    assert problems_for(text) == []


def test_a_pqc_signature_needs_the_pqc_variant():
    assert problems_for(config_text(pqc="false")) == [
        "signature_pqc.ml_dsa_87 needs [variants] pqc, the only variant that "
        "carries a PQC signature"]


@pytest.mark.parametrize("changes, problem", [
    ({"rsa": "false"},
     "der.rsa_public_key needs signature_classic.rsa_3072_pkcs1v15_sha256 enabled"),
    ({"ecdsa": "false"},
     "der.ecdsa_signature needs signature_classic.ecdsa_p256_sha256 enabled"),
], ids=["rsa", "ecdsa"])
def test_a_der_encoding_needs_an_algorithm_of_its_family(changes, problem):
    """The message names only the algorithms a configuration can turn on."""
    assert problems_for(config_text(**changes)) == [problem]


def test_a_der_encoding_offers_every_implemented_algorithm_of_its_family(monkeypatch):
    """With more than one to choose from, the message lists them all."""
    der = next(s for s in gen_config.SETTINGS if s.name == "der.ecdsa_signature")
    second = gen_config.Setting("signature_classic", "ecdsa_p384_sha384",
                                "OCA_CFG_SIG_ECDSA_P384_SHA384", "bool", "ECDSA P-384",
                                required=False, code=0x06)
    settings = tuple(second if s.name == second.name else s for s in gen_config.SETTINGS)
    monkeypatch.setattr(gen_config, "SETTINGS", settings)
    problems = gen_config._cross_setting_problems({}, {der.name})
    assert ("der.ecdsa_signature needs one of signature_classic.ecdsa_p256_sha256, "
            "signature_classic.ecdsa_p384_sha384 enabled") in problems


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


def test_a_missing_relative_path_names_where_it_was_looked_for(tmp_path, monkeypatch):
    """The Makefile resolves CONFIG from its own directory, so a relative path
    can name a file other than the one the user meant. The message says which
    file was tried."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.load_config("absent.toml")
    assert f"(looked for {os.path.abspath('absent.toml')})" in caught.value.problems[0]


def test_a_missing_absolute_path_is_named_once(tmp_path):
    path = str(tmp_path / "absent.toml")
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.load_config(path)
    assert "looked for" not in caught.value.problems[0]
    assert caught.value.problems[0].startswith(f"cannot read {path}: ")


def test_an_invalid_configuration_raises_before_writing(tmp_path):
    config = write_config(tmp_path, config_text(pqc="2"))
    out = tmp_path / "gen" / "oca_config.h"
    with pytest.raises(gen_config.ConfigError) as caught:
        gen_config.generate(config, str(out))
    assert caught.value.problems == ["variants.pqc must be true or false, not 2"]
    assert not out.exists()


def test_the_header_holds_every_setting_and_its_portfolio(tmp_path):
    config = write_config(tmp_path, config_text(toc_max_images="32", pqc="false",
                                                ml_dsa_87="false"))
    header = gen_config.header_for_config(config)
    assert "#define OCA_CFG_FORMAT 1\n" in header
    assert "#define OCA_CFG_TOC_MAX_IMAGES 32u\n" in header
    assert "#define OCA_CFG_VARIANT_CLASSIC 1\n" in header
    text = header_portfolio_text(header)
    assert "limits.toc_max_images=32\n" in text
    assert "variants.pqc" not in text
    assert text.splitlines() == sorted(text.splitlines())
    digest = gen_config.hashlib.sha256(text.encode("ascii")).digest()
    assert header_portfolio_digest(header) == digest
    assert f"#define OCA_CFG_PORTFOLIO_ID 0x{digest[:4].hex()}u\n" in header


def header_portfolio_text(header):
    """The OCA_CFG_PORTFOLIO_TEXT a header holds, as the string C reads it."""
    block = header[header.index("#define OCA_CFG_PORTFOLIO_TEXT"):
                   header.index("#define OCA_CFG_PORTFOLIO_DIGEST")]
    return "".join(literal.replace("\\n", "\n")
                   for literal in re.findall(r'"([^"]*)"', block))


def header_portfolio_digest(header):
    """The bytes of the OCA_CFG_PORTFOLIO_DIGEST initializer a header holds."""
    block = header[header.index("#define OCA_CFG_PORTFOLIO_DIGEST"):
                   header.index("#define OCA_CFG_PORTFOLIO_ID")]
    return bytes(int(byte, 16) for byte in re.findall(r"0x([0-9a-f]{2})\b", block))


def portfolio_of(directory, text, name="board.toml"):
    """The portfolio digest of the configuration text, read from a file name."""
    document = gen_config.load_config(write_config(directory, text, name))
    return gen_config.portfolio_digest(gen_config.resolve_settings(document))


def toml_spelling(value) -> str:
    """A value as TOML text, an integer in hexadecimal."""
    if isinstance(value, bool):
        return build_config.toml_text(value)
    return hex(value)


def reordered_text(document) -> str:
    """document as TOML with comments, its sections in reverse order, and the
    keys inside each in reverse order too."""
    blocks = [f"# The {section} section.\n[{section}]\n"
              + "".join(f"{key} = {build_config.toml_text(value)}  # {key}\n"
                        for key, value in reversed(table.items()))
              for section, table in reversed(document.items())]
    return "# A board's configuration.\n\n" + "\n".join(blocks)


def dotted_text(document) -> str:
    """document as dotted keys at the top level, every integer in hexadecimal."""
    return "".join(f"{section}.{key} = {toml_spelling(value)}\n"
                   for section, table in document.items() for key, value in table.items())


def inline_text(document) -> str:
    """document as one inline table per section, every integer in hexadecimal."""
    return "".join(f"{section} = {{ "
                   + ", ".join(f"{key} = {toml_spelling(value)}" for key, value in table.items())
                   + " }\n"
                   for section, table in document.items())


@pytest.mark.parametrize("spelling", [reordered_text, dotted_text, inline_text],
                         ids=["reordered", "dotted", "inline"])
def test_the_portfolio_depends_on_the_settings_not_the_file(tmp_path, spelling):
    """Comments, the order of sections and keys, how TOML spells a table or an
    integer, and the file's name all leave the digest alone."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    respelled = spelling(gen_config.tomllib.loads(config_text()))
    assert respelled != config_text()
    assert portfolio_of(tmp_path / "a", config_text()) \
        == portfolio_of(tmp_path / "b", respelled, name="other.toml")


# Changes to the shipped default that each leave a valid configuration with a
# portfolio of its own, including two values of one setting and two settings
# turned off alone.
PORTFOLIO_CHANGES = {
    "default": {},
    "toc_max_images=32": {"toc_max_images": "32"},
    "toc_max_images=33": {"toc_max_images": "33"},
    "recheck_security_version off": {"recheck_security_version": "false"},
    "der_rsa off": {"der_rsa": "false"},
    "der_ecdsa off": {"der_ecdsa": "false"},
    "aes_128 off": {"aes_128": "false"},
    "aes_256 off": {"aes_256": "false"},
    "pqc off": {"pqc": "false", "ml_dsa_87": "false"},
}


def test_every_portfolio_has_its_own_digest_and_identifier(tmp_path):
    digests = {}
    for label, changes in PORTFOLIO_CHANGES.items():
        (tmp_path / label).mkdir()
        digests[label] = portfolio_of(tmp_path / label, config_text(**changes))
    assert len(set(digests.values())) == len(digests), digests
    identifiers = {digest[:4] for digest in digests.values()}
    assert len(identifiers) == len(digests), digests


def test_a_switch_left_off_does_not_change_the_portfolio(tmp_path):
    """A switch at zero contributes nothing, whether left out or stated false,
    and whether or not the library implements it: an upgrade that adds one left
    off keeps every existing identifier."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    stated = config_text().replace("ml_dsa_87 = true\n",
                                   "ml_dsa_87 = true\nml_dsa_44 = false\n")
    stated = stated.replace("[encryption_cipher]\n", "[encryption_cipher]\nsm4_128_cbc = false\n")
    assert portfolio_of(tmp_path / "a", config_text()) == portfolio_of(tmp_path / "b", stated)


def test_an_optional_setting_stated_false_does_not_change_the_portfolio(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert "disabled = false\n" in config_text()
    assert portfolio_of(tmp_path / "a", config_text()) \
        == portfolio_of(tmp_path / "b", config_text(secure_boot_disabled=None))


def test_a_comment_only_edit_leaves_the_header_alone(tmp_path):
    """The header holds nothing of the file but its name, so editing a comment
    rebuilds nothing."""
    out = tmp_path / "oca_config.h"
    assert gen_config.generate(write_config(tmp_path, config_text()), str(out)) is True
    edited = write_config(tmp_path, "# Reviewed.\n" + config_text())
    assert gen_config.generate(edited, str(out)) is False


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


def test_a_switch_the_library_does_not_implement_has_no_value(tmp_path):
    """Stating one off is allowed, and generates nothing: no macro, and no
    entry in the resolved values."""
    text = config_text().replace("ml_dsa_87 = true\n", "ml_dsa_87 = true\nml_dsa_44 = false\n")
    values = gen_config.resolve_settings(gen_config.tomllib.loads(text))
    assert "" not in values
    assert set(values) == {s.macro for s in IMPLEMENTED}


def test_the_header_is_written_with_lf_line_endings(tmp_path):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    gen_config.generate(config, str(out))
    assert b"\r" not in out.read_bytes()


def test_a_header_with_crlf_line_endings_is_not_current(tmp_path):
    """A header converted to CRLF, as a checkout on another host can do, differs
    from what the generator writes, so --check reports it and a build rewrites
    it."""
    out = tmp_path / "oca_config.h"
    text = gen_config.header_for_config(write_config(tmp_path, config_text()))
    out.write_bytes(text.replace("\n", "\r\n").encode())
    assert gen_config.header_is_current(str(out), text) is False


def test_a_header_is_current_only_when_it_matches_exactly(tmp_path):
    out = tmp_path / "oca_config.h"
    text = gen_config.header_for_config(write_config(tmp_path, config_text()))
    assert gen_config.header_is_current(str(out), text) is False
    out.write_text(text)
    assert gen_config.header_is_current(str(out), text) is True
    out.write_text(text + "\n")
    assert gen_config.header_is_current(str(out), text) is False


def refuse_to_replace(source, destination):
    raise OSError(28, "No space left on device")


def test_a_failed_write_keeps_the_previous_header_and_leaves_no_temporary(
        tmp_path, monkeypatch):
    out = tmp_path / "gen" / "oca_config.h"
    gen_config.generate(write_config(tmp_path, config_text()), str(out))
    previous = out.read_text()
    changed = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    monkeypatch.setattr(gen_config.os, "replace", refuse_to_replace)
    with pytest.raises(OSError):
        gen_config.generate(changed, str(out))
    assert out.read_text() == previous
    assert sorted(path.name for path in out.parent.iterdir()) == ["oca_config.h"]


@pytest.fixture
def restore_umask():
    """Puts the process umask back after a test that sets its own."""
    previous = os.umask(0o022)
    yield
    os.umask(previous)


@pytest.mark.parametrize("mask, mode", [
    pytest.param(0o022, 0o644, id="umask-022"),
    pytest.param(0o002, 0o664, id="umask-002"),
    pytest.param(0o077, 0o600, id="umask-077"),
])
def test_the_header_gets_the_mode_any_new_file_would(tmp_path, restore_umask, mask, mode):
    """The header is written through a temporary file, which is created private;
    it must not stay private, or a build run by one user cannot be read by
    another, or by a container running as someone else."""
    os.umask(mask)
    out = tmp_path / "gen" / "oca_config.h"
    gen_config.generate(write_config(tmp_path, config_text()), str(out))
    assert out.stat().st_mode & 0o777 == mode
    changed = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    assert gen_config.generate(changed, str(out))
    assert out.stat().st_mode & 0o777 == mode


def refuse_to_set_the_umask(mask):
    raise AssertionError("the generator set the process umask")


def test_writing_the_header_leaves_the_umask_alone(tmp_path, monkeypatch):
    """Changing the umask, even briefly, can give another thread's new file the
    wrong mode."""
    monkeypatch.setattr(gen_config.os, "umask", refuse_to_set_the_umask)
    out = tmp_path / "gen" / "oca_config.h"
    assert gen_config.generate(write_config(tmp_path, config_text()), str(out))
    changed = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    assert gen_config.generate(changed, str(out))


def repeat_then_vary(values):
    """An os.urandom stand-in that returns each of values in turn."""
    remaining = iter(values)
    return lambda size: next(remaining)


def test_a_file_already_at_the_temporary_name_is_left_alone(tmp_path, monkeypatch):
    """The temporary file is created exclusively, so a name already in use is
    skipped rather than overwritten."""
    out = tmp_path / "oca_config.h"
    taken = tmp_path / f".oca_config.h.{'00' * 6}.tmp"
    taken.write_text("someone else's file")
    monkeypatch.setattr(gen_config.os, "urandom", repeat_then_vary([b"\0" * 6, b"\1" * 6]))
    config = write_config(tmp_path, config_text())
    assert gen_config.generate(config, str(out))
    assert out.read_text() == gen_config.header_for_config(config)
    assert taken.read_text() == "someone else's file"
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        taken.name, "board.toml", "oca_config.h"]


def test_a_header_that_is_not_utf8_is_stale_and_rewritten(tmp_path, capsys):
    """A damaged header must not stop the build that would repair it."""
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    out.write_bytes(b"\xff\xfe not a header\n")
    assert gen_config.header_is_current(str(out), gen_config.header_for_config(config)) is False
    assert gen_config.main(["--config", config, "--out", str(out), "--check"]) == 1
    assert "is missing or stale" in capsys.readouterr().err
    assert gen_config.main(["--config", config, "--out", str(out)]) == 0
    assert out.read_text() == gen_config.header_for_config(config)


@pytest.mark.parametrize("check", [False, True], ids=["write", "check"])
def test_a_header_path_that_is_a_directory_is_reported_in_one_line(tmp_path, capsys, check):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    out.mkdir()
    flags = ["--check"] if check else []
    assert gen_config.main(["--config", config, "--out", str(out), *flags]) == 2
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1, lines
    assert lines[0].startswith(f"gen_config: {out}: ")


def refuse_to_open_the_header(path, *args, **kwargs):
    """An open() stand-in that refuses only oca_config.h."""
    if str(path).endswith("oca_config.h"):
        raise PermissionError(13, "Permission denied")
    return builtins.open(path, *args, **kwargs)


@pytest.mark.parametrize("check", [False, True], ids=["write", "check"])
def test_a_header_that_cannot_be_read_is_reported_in_one_line(
        tmp_path, capsys, monkeypatch, check):
    config = write_config(tmp_path, config_text())
    out = tmp_path / "oca_config.h"
    gen_config.generate(config, str(out))
    monkeypatch.setattr(gen_config, "open", refuse_to_open_the_header, raising=False)
    with pytest.raises(PermissionError):
        gen_config.generate(config, str(out))
    flags = ["--check"] if check else []
    assert gen_config.main(["--config", config, "--out", str(out), *flags]) == 2
    assert capsys.readouterr().err == f"gen_config: {out}: Permission denied\n"


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


@pytest.mark.parametrize("name, printed", [
    ("signature_pqc.ml_dsa_87", "1"),
    ("der.ecdsa_signature", "0"),
    ("signature_pqc.ml_dsa_44", "0"),
    ("limits.toc_max_images", "16"),
], ids=["on", "off", "not-implemented", "count"])
def test_print_writes_one_resolved_value(tmp_path, capsys, name, printed):
    config = write_config(tmp_path, config_text(toc_max_images="16", der_ecdsa="false"))
    assert gen_config.main(["--config", config, "--print", name]) == 0
    assert capsys.readouterr().out == f"{printed}\n"
    assert os.listdir(tmp_path) == ["board.toml"]


def test_print_refuses_a_name_that_is_no_setting(tmp_path, capsys):
    config = write_config(tmp_path, config_text())
    assert gen_config.main(["--config", config, "--print", "ml_dsa_87"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no setting is named ml_dsa_87" in captured.err


def test_print_all_writes_every_setting(tmp_path, capsys):
    config = write_config(tmp_path, config_text(aes_128="false"))
    assert gen_config.main(["--config", config, "--print-all"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [line.split("=")[0] for line in lines] == [s.name for s in gen_config.SETTINGS]
    printed = dict(line.split("=") for line in lines)
    assert printed["encryption_cipher.aes_128_cbc"] == "0"
    assert printed["encryption_cipher.aes_256_cbc"] == "1"
    assert printed["limits.toc_max_images"] == "256"


def test_print_all_states_the_portfolio_the_header_names(tmp_path, capsys):
    """Every line of --print-all that is not zero is a line of the portfolio,
    so a build system can name the header's portfolio from the file alone."""
    config = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    assert gen_config.main(["--config", config, "--print-all"]) == 0
    lines = capsys.readouterr().out.splitlines()
    stated = "".join(f"{line}\n" for line in sorted(lines) if not line.endswith("=0"))
    assert stated == header_portfolio_text(gen_config.header_for_config(config))


def test_print_refuses_an_invalid_configuration(tmp_path, capsys):
    config = write_config(tmp_path, config_text(pqc="2"))
    assert gen_config.main(["--config", config, "--print", "variants.pqc"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "variants.pqc must be true or false, not 2" in captured.err


@pytest.mark.parametrize("argv", [
    ["--config", "board.toml"],
    ["--config", "board.toml", "--out", "oca_config.h", "--check", "--print-all"],
    ["--config", "board.toml", "--print", "variants.pqc", "--print-all"],
], ids=["no-out-nothing-to-print", "check-and-print", "print-twice"])
def test_the_command_line_refuses_a_contradictory_request(argv):
    with pytest.raises(SystemExit) as caught:
        gen_config.main(argv)
    assert caught.value.code == 2


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
    assert re.search(rf"^#ifndef {setting.macro}\n#error \"oca_config.h is missing "
                     rf"{setting.macro}; regenerate it\"\n#endif$",
                     _check_header_text(), re.M)


# Settings that declare a kind of build, and are refused in a configuration
# that is not one.
DECLARATIONS = {"OCA_CFG_SECURE_BOOT_DISABLED"}


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
    generated = {s.macro for s in IMPLEMENTED} | {
        "OCA_CFG_FORMAT", "OCA_CFG_IS_SWITCH", "OCA_CFG_PORTFOLIO_TEXT",
        "OCA_CFG_PORTFOLIO_DIGEST", "OCA_CFG_PORTFOLIO_ID", "OCA_CFG_PORTFOLIO_SEAL_",
        "OCA_CFG_ID_OF", "OCA_CFG_ID_OF_BYTES", "OCA_CFG_SEAL_PREFIX", "OCA_CFG_SEAL_EXPAND",
        "OCA_CFG_SEAL_PASTE"}
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
    document = gen_config.load_config(DEFAULT_CONFIG)
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
                 "oca_config.h was generated for another version of this library",
                 id="other-format"),
    pytest.param({"drop": ["OCA_CFG_PORTFOLIO_ID"]},
                 "oca_config.h is missing OCA_CFG_PORTFOLIO_ID",
                 id="no-portfolio"),
    pytest.param({"drop": ["OCA_CFG_PORTFOLIO_DIGEST"]},
                 "oca_config.h is missing OCA_CFG_PORTFOLIO_DIGEST",
                 id="no-portfolio-digest"),
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
    pytest.param({"values": {"OCA_CFG_SECURE_BOOT_DISABLED": "2"}},
                 "holds a true/false setting that is neither 0 nor 1",
                 id="secure-boot-disabled-not-bool"),
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


# ---------------------------------------------------------------------------
# The Makefile
# ---------------------------------------------------------------------------


def run_make(build_dir, *args, environment=None):
    require_tools("make", "cc")
    return subprocess.run(
        ["make", "-C", VALIDATOR_DIR, f"BUILD={build_dir}", *args],
        capture_output=True, text=True,
        env={**os.environ, "PYTHON": sys.executable, **(environment or {})})


def test_a_config_variable_in_the_environment_does_not_choose_the_configuration(
        tmp_path):
    """CONFIG is a common name for an unrelated environment variable, so only the
    make command line names the build configuration."""
    build = tmp_path / "build"
    stray = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    result = run_make(build, str(build / "gen" / "oca_config.h"),
                      environment={"CONFIG": stray})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (build / "gen" / "oca_config.h").read_text() == default_header()


def test_an_invalid_configuration_stops_the_build_before_any_compile(tmp_path):
    config = write_config(tmp_path, config_text(toc_max_images="0"))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "lib")
    assert result.returncode != 0
    assert "limits.toc_max_images must be between 1" in result.stderr
    assert not list((tmp_path / "build").rglob("*.o"))


def test_the_build_runs_the_generator_isolated_from_pythonpath(tmp_path):
    """Without -I, a module on PYTHONPATH with the same name as one the
    generator imports would run inside the build."""
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "tomllib.py").write_text('raise SystemExit("a shadowing tomllib ran")\n')
    build = tmp_path / "build"
    result = run_make(build, str(build / "gen" / "oca_config.h"),
                      environment={"PYTHONPATH": str(shadow)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (build / "gen" / "oca_config.h").read_text() == default_header()


# Every place that tells someone how to run the generator, and the Makefile
# that runs it.
GENERATOR_RUNNERS = [os.path.join(VALIDATOR_DIR, "Makefile"),
                     os.path.join(VALIDATOR_DIR, "README.md"),
                     os.path.join(VALIDATOR_DIR, "INTEGRATION.md"),
                     GENERATOR]
INTERPRETER = r"(?:python3|\$\{Python3_EXECUTABLE\}|\$\(CONFIG_PYTHON\))"


def runs_without_isolation(text):
    """Every line of text that runs gen_config.py with an interpreter but
    without -I."""
    return [line for line in text.splitlines()
            if re.search(rf"{INTERPRETER}\s.*gen_config\.py", line)
            and not re.search(rf"{INTERPRETER} -I \S*gen_config\.py", line)]


@pytest.mark.parametrize("path", GENERATOR_RUNNERS, ids=os.path.basename)
def test_every_documented_run_of_the_generator_is_isolated(path):
    with open(path) as handle:
        text = handle.read()
    assert "gen_config.py" in text
    assert runs_without_isolation(text) == []


def test_a_run_without_isolation_is_found():
    """The check above is only worth having if it notices a missing -I."""
    assert runs_without_isolation(
        "python3 lib/scripts/gen_config.py --config a.toml\n"
        "  COMMAND ${Python3_EXECUTABLE} ${OCA_LIB}/scripts/gen_config.py\n"
        "\t@$(CONFIG_PYTHON) lib/scripts/gen_config.py --out $@\n"
        "python3 -I lib/scripts/gen_config.py --config a.toml\n") == [
        "python3 lib/scripts/gen_config.py --config a.toml",
        "  COMMAND ${Python3_EXECUTABLE} ${OCA_LIB}/scripts/gen_config.py",
        "\t@$(CONFIG_PYTHON) lib/scripts/gen_config.py --out $@"]


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


@pytest.mark.parametrize("target", ["lib", "unit_test"])
def test_a_setting_read_by_a_name_nothing_defines_stops_the_build(tmp_path, target):
    """An undefined macro in #if reads as 0. Without -Wundef, a misspelled
    setting, or code still testing a setting's former name, would silently
    compile its feature out."""
    stale = tmp_path / "stale.h"
    stale.write_text("#if OCA_SUPPORT_PQC\n#endif\n")
    result = run_make(tmp_path / "build", f"EXTRA_CFLAGS=-include {stale}", target)
    assert result.returncode != 0
    assert "OCA_SUPPORT_PQC" in result.stderr


# Between them, these turn off each variant, each signature algorithm, each DER
# encoding while its algorithm stays on, each cipher, payload encryption as a
# whole, the recheck, and everything but a hash.
UNIT_TEST_CONFIGURATIONS = [
    pytest.param({}, (), id="default"),
    pytest.param({"toc_max_images": "16", "recheck_security_version": "false"},
                 ("test_anti_rollback_evaluated_once_when_recheck_disabled",),
                 id="small-toc-no-recheck"),
    pytest.param({"pqc": "false", "ml_dsa_87": "false"}, (), id="classic-only"),
    pytest.param({"classic": "false"}, (), id="pqc-only"),
    pytest.param({"ecdsa": "false", "der_ecdsa": "false", "ml_dsa_87": "false",
                  "der_rsa": "false", "aes_128": "false"}, (),
                 id="rsa-raw-keys-aes-256"),
    pytest.param({"rsa": "false", "der_rsa": "false", "der_ecdsa": "false",
                  "aes_128": "false", "aes_256": "false", "kdf": "false",
                  "preshared": "false"}, (),
                 id="ecdsa-raw-signatures-ml-dsa-no-encryption"),
    pytest.param({"rsa": "false", "ecdsa": "false", "der_rsa": "false",
                  "der_ecdsa": "false", "aes_256": "false"}, (),
                 id="ml-dsa-aes-128"),
    pytest.param({**NO_SECURE_BOOT, "secure_boot_disabled": "true"}, (),
                 id="hash-only"),
    # The largest cap the generator allows, where cap + 1 wraps a 32-bit count.
    pytest.param({"toc_max_images": "4294967295"}, (), id="largest-toc"),
]

# The tests of each setting's off branch, and the sweeps that hold the
# algorithm tables to the configuration. They run under every configuration.
TESTS_OF_THE_CONFIGURATION = (
    "test_a_variant_the_build_leaves_off_is_unsupported",
    "test_a_signature_algorithm_the_build_leaves_off_is_refused",
    "test_a_der_encoding_the_build_leaves_off_is_refused",
    "test_a_cipher_the_build_leaves_off_is_refused_before_hashing",
    "test_every_payload_algorithm_resolves_against_the_format_and_the_build",
    "test_a_build_without_secure_boot_refuses_every_check_it_left_out",
)

# The sweeps of the signature-algorithm table, which a build that declares
# [secure_boot] disabled compiles out with the lookups they call: they run
# wherever secure boot is built, and are listed as not run where it is not.
TESTS_OF_THE_SIGNATURE_TABLE = (
    "test_every_signature_type_resolves_against_the_format_and_the_build",
    "test_signature_rows_carry_the_format_encoded_lengths",
)


@pytest.mark.parametrize("changes, also_passing", UNIT_TEST_CONFIGURATIONS)
def test_the_unit_tests_pass_under_every_build_configuration(tmp_path, changes,
                                                             also_passing):
    """A unit test whose fixtures need something a configuration turns off is
    registered with what it needs, and is listed as not run where the build
    lacks it; every test that runs must pass. Under the default every test
    runs, so a test gated wrongly is caught there."""
    config = write_config(tmp_path, config_text(**changes))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "unit_test")
    # The driver reports on stderr.
    assert result.returncode == 0, result.stdout + result.stderr
    summary = re.search(r"^(\d+)/(\d+) passed$", result.stderr, re.M)
    assert summary and summary.group(1) == summary.group(2), result.stderr
    for name in (*TESTS_OF_THE_CONFIGURATION, *also_passing):
        assert f"PASS: {name}\n" in result.stderr, name
    secure_boot_built = changes.get("secure_boot_disabled") != "true"
    for name in TESTS_OF_THE_SIGNATURE_TABLE:
        line = f"PASS: {name}\n" if secure_boot_built else f"NOT RUN: {name} ("
        assert line in result.stderr, name
    if not changes:
        assert "NOT RUN:" not in result.stderr


# The functions only a build with secure boot contains: the checks a build that
# declares [secure_boot] disabled compiles out, and the helpers and lookups
# only they call.
SECURE_BOOT_ONLY = {
    "authorize_key_by_class", "check_revocation_by_class", "verify_signature_by_class",
    "check_class_algorithm", "check_cohort", "classical_revoke_bit", "pqc_revoke_bit",
    "commit_revocation_for_family", "padding_is_dirty", "required_size", "empty_blob",
    "check_class_description", "oca_check_class_description", "oca_signature_algorithm",
    "oca_encoding_status", "classical_signature_defined", "pqc_signature_defined",
    "oca_secure_boot_confirm_classes", "check_encrypted_payload",
}

# The entry points of those checks, which every build defines: a build without
# secure boot defines each as a stub.
SECURE_BOOT_ENTRY_POINTS = {
    "oca_check_signing_description", "oca_check_signature_posture",
    "oca_check_root_key_authorized", "oca_check_root_key_revocation",
    "oca_check_security_version", "oca_check_signature", "oca_commit_security_state",
}


def defined_functions(directory, header_text):
    """Every function the library defines when compiled against header_text.

    Compiled without optimization, so a static function keeps its symbol
    rather than being inlined away, and its absence means its source was not
    compiled.
    """
    require_tools("cc", "nm")
    gen = directory / "gen"
    gen.mkdir(parents=True)
    (gen / "oca_config.h").write_text(header_text)
    names = set()
    for source in sorted(os.listdir(LIB_DIR)):
        if not source.endswith(".c"):
            continue
        obj = directory / (source[:-2] + ".o")
        subprocess.run(["cc", "-std=c99", "-O0", "-c", "-I", LIB_DIR, "-I", str(gen),
                        os.path.join(LIB_DIR, source), "-o", str(obj)], check=True)
        listed = subprocess.run(["nm", str(obj)], capture_output=True, text=True,
                                check=True)
        for line in listed.stdout.splitlines():
            words = line.split()
            if len(words) == 3 and words[1] in ("t", "T"):
                names.add(words[2][1:] if sys.platform == "darwin" else words[2])
    return names


def test_a_build_without_secure_boot_compiles_its_checks_out(tmp_path):
    full = defined_functions(tmp_path / "full", default_header())
    hash_only = defined_functions(
        tmp_path / "hash-only",
        gen_config.header_for_config(os.path.join(BUILD_CONFIG_DIR, "hash_only.toml")))
    assert SECURE_BOOT_ONLY <= full, SECURE_BOOT_ONLY - full
    assert SECURE_BOOT_ONLY & hash_only == set()
    assert SECURE_BOOT_ENTRY_POINTS <= hash_only
    assert hash_only - full == {"oca_secure_boot_not_built"}


# ---------------------------------------------------------------------------
# The library's code points, against the generator's
# ---------------------------------------------------------------------------

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
    require_tools("cc")
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    (gen / "oca_config.h").write_text(header_text)
    probe = tmp_path / "code_points.c"
    probe.write_text(CODE_POINT_PROBE)
    binary = tmp_path / "code_points"
    sources = [os.path.join(lib_dir, name) for name in sorted(os.listdir(lib_dir))
               if name.endswith(".c") and name != "signature_posture.c"]
    built = subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Werror", "-pedantic", "-I", str(lib_dir),
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

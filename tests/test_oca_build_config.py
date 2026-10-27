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
SETTING_IDS = [setting.name for setting in gen_config.SETTINGS]

DEFAULT_VALUES = {
    "OCA_CFG_VARIANT_CLASSIC": 1,
    "OCA_CFG_VARIANT_PQC": 1,
    "OCA_CFG_TOC_MAX_IMAGES": 256,
    "OCA_CFG_RECHECK_SECURITY_VERSION": 1,
}


def config_text(classic="true", pqc="true", toc_max_images="256",
                recheck_security_version="true", extra=""):
    """A complete configuration, every value given as its TOML text."""
    return (
        "[variants]\n"
        f"classic = {classic}\n"
        f"pqc = {pqc}\n"
        "\n[limits]\n"
        f"toc_max_images = {toc_max_images}\n"
        "\n[hardening]\n"
        f"recheck_security_version = {recheck_security_version}\n"
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


@pytest.mark.parametrize("name, classic, pqc", [
    ("classic_only.toml", 1, 0),
    ("pqc_only.toml", 0, 1),
])
def test_the_variant_build_configs_differ_from_the_default_only_in_variants(
        name, classic, pqc):
    document, _ = gen_config.load_config(os.path.join(BUILD_CONFIG_DIR, name))
    expected = {**DEFAULT_VALUES, "OCA_CFG_VARIANT_CLASSIC": classic,
                "OCA_CFG_VARIANT_PQC": pqc}
    assert gen_config.resolve_settings(document) == expected


def test_a_complete_configuration_is_accepted():
    assert problems_for(config_text()) == []


@pytest.mark.parametrize("setting", gen_config.SETTINGS, ids=SETTING_IDS)
def test_every_setting_is_required(setting):
    """A configuration replaces the default, so leaving a setting out is refused,
    never filled in from a default nobody reviewed."""
    text = "".join(line + "\n" for line in config_text().splitlines()
                   if not line.startswith(f"{setting.key} ="))
    assert problems_for(text) == [
        f"{setting.name} is required: a configuration replaces the default, "
        f"so every setting must be stated"]


def test_an_empty_configuration_names_every_setting():
    assert len(problems_for("")) == len(gen_config.SETTINGS)


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
    assert problems_for(config_text(classic="false", pqc="false")) == [
        "[variants] must enable at least one of classic and pqc"]


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
    changed = write_config(tmp_path, config_text(pqc="false"))
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


@pytest.mark.parametrize("setting", gen_config.SETTINGS, ids=SETTING_IDS)
def test_the_check_header_requires_every_setting(setting):
    guard = re.search(r"#if (!defined\(OCA_CFG_VARIANT_CLASSIC\).*?)\n#error",
                      _check_header_text(), re.S)
    assert guard and f"!defined({setting.macro})" in guard.group(1)


@pytest.mark.parametrize("setting", gen_config.SETTINGS, ids=SETTING_IDS)
def test_every_setting_reaches_the_library(setting):
    """A setting nothing reads would be a configuration key with no effect."""
    readers = []
    for name in sorted(os.listdir(LIB_DIR)):
        if name.endswith((".c", ".h")) and name != "oca_config_check.h":
            with open(os.path.join(LIB_DIR, name)) as handle:
                if setting.macro in handle.read():
                    readers.append(name)
    assert readers, f"{setting.macro} is generated but no library source reads it"


# ---------------------------------------------------------------------------
# The check header, compiled against headers the generator would never write
# ---------------------------------------------------------------------------


PROBE = '#include "oca_validator.h"\nint oca_probe;\n'


def compile_probe(tmp_path, header_text, *defines):
    """Compile a translation unit that includes the library's public header.

    header_text becomes the oca_config.h on the include path; None leaves it
    out entirely. Returns the completed compiler run.
    """
    require_tools("cc")
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    if header_text is not None:
        (gen / "oca_config.h").write_text(header_text)
    probe = tmp_path / "probe.c"
    probe.write_text(PROBE)
    return subprocess.run(
        ["cc", "-std=c99", "-Wall", "-Werror", "-pedantic", "-fsyntax-only",
         "-I", LIB_DIR, "-I", str(gen), *defines, str(probe)],
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


@pytest.mark.parametrize("setting", gen_config.SETTINGS, ids=SETTING_IDS)
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
    write_config(tmp_path, config_text(pqc="false"))
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

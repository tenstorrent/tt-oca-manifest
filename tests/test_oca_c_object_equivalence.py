# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Unit coverage for `check_object_equivalence.py`.

That script is the gate that proves a comment-only change altered no object
code. A gate whose own correctness is unverified can pass while broken — the
worst possible failure for a check whose entire value is being trusted — so the
comparison and its report are exercised here against synthetic object files,
which needs no compiler and can express the failing cases the real tree cannot.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys

import pytest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(
    PROJECT_ROOT, "validators", "oca", "lib", "scripts")
EQUIVALENCE = os.path.join(SCRIPTS_DIR, "check_object_equivalence.py")


def _load(path, name):
    """Import a standalone script by path; it is not on any package path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


equivalence = _load(EQUIVALENCE, "oca_object_equivalence")


def make_objects(directory, contents):
    """Write fake object files so the comparison can be tested without a compiler."""
    os.makedirs(directory, exist_ok=True)
    for name, data in contents.items():
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(data)
    return directory


def test_identical_objects_compare_equal(tmp_path):
    payload = {"a.o": b"\x01\x02", "b.o": b"\x03"}
    baseline = make_objects(str(tmp_path / "base"), payload)
    current = make_objects(str(tmp_path / "cur"), payload)
    results = equivalence.compare_object_dirs(baseline, current)
    assert [r.name for r in results] == ["a.o", "b.o"]
    assert all(r.identical for r in results)


def test_differing_object_is_detected_and_named(tmp_path):
    """The failure this gate exists for: a change that altered code, not comments."""
    baseline = make_objects(str(tmp_path / "base"), {"a.o": b"\x01", "b.o": b"\x03"})
    current = make_objects(str(tmp_path / "cur"), {"a.o": b"\x01", "b.o": b"\x04"})
    results = equivalence.compare_object_dirs(baseline, current)
    differing = [r.name for r in results if not r.identical]
    assert differing == ["b.o"]


def test_object_present_in_only_one_tree_counts_as_differing(tmp_path):
    """A source file added or removed is not a comment-only change either."""
    baseline = make_objects(str(tmp_path / "base"), {"a.o": b"\x01"})
    current = make_objects(str(tmp_path / "cur"), {"a.o": b"\x01", "new.o": b"\x02"})
    results = equivalence.compare_object_dirs(baseline, current)
    assert [r.name for r in results if not r.identical] == ["new.o"]


def test_report_states_pass_when_everything_matches(tmp_path):
    payload = {"a.o": b"\x01"}
    results = equivalence.compare_object_dirs(
        make_objects(str(tmp_path / "base"), payload),
        make_objects(str(tmp_path / "cur"), payload))
    report = equivalence.format_report(results, "abc1234")
    assert "1/1 identical — PASS" in report
    assert "abc1234" in report


def test_report_names_the_offending_file_on_failure(tmp_path):
    results = equivalence.compare_object_dirs(
        make_objects(str(tmp_path / "base"), {"payload.o": b"\x01"}),
        make_objects(str(tmp_path / "cur"), {"payload.o": b"\x02"}))
    report = equivalence.format_report(results, "abc1234")
    assert "FAIL" in report
    assert "payload.o differs." in report


def test_equivalence_gate_rejects_an_unknown_baseline_ref():
    """Exit 2 is a setup failure, distinct from exit 1 meaning objects differ —
    a broken invocation must never look like a clean comparison."""
    completed = subprocess.run(
        [sys.executable, EQUIVALENCE, "--baseline", "no-such-ref-exists"],
        cwd=PROJECT_ROOT, capture_output=True, text=True)
    assert completed.returncode == 2


LIB_DIR = os.path.dirname(SCRIPTS_DIR)


def make_lib_tree(directory, config_text=None):
    """A stand-in lib/ directory: the real generator, and optionally a default config."""
    scripts = directory / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(os.path.join(SCRIPTS_DIR, "gen_config.py"), scripts / "gen_config.py")
    if config_text is not None:
        (directory / "oca_config.toml").write_text(config_text)
    return directory


def test_a_tree_without_a_generator_needs_no_config_include(tmp_path):
    """A baseline from before the generated configuration still builds."""
    (tmp_path / "lib").mkdir()
    assert equivalence.generate_config_header(
        str(tmp_path / "lib"), str(tmp_path / "out")) == []


def test_a_tree_with_a_generator_builds_from_its_own_default(tmp_path):
    with open(os.path.join(LIB_DIR, "oca_config.toml")) as handle:
        lib = make_lib_tree(tmp_path / "lib", handle.read())
    include = equivalence.generate_config_header(str(lib), str(tmp_path / "out"))
    assert include == ["-I", str(tmp_path / "out" / "gen")]
    assert (tmp_path / "out" / "gen" / "oca_config.h").exists()


def test_a_tree_whose_default_config_is_invalid_reports_the_failure(tmp_path):
    lib = make_lib_tree(tmp_path / "lib", "[variants]\nclassic = 1\n")
    error = equivalence.generate_config_header(str(lib), str(tmp_path / "out"))
    assert isinstance(error, str)
    assert "variants.classic must be true or false" in error


def test_a_failed_config_generation_stops_the_build(tmp_path):
    lib = make_lib_tree(tmp_path / "lib", "not toml at all [")
    (lib / "unit.c").write_text("int unit;\n")
    error = equivalence.build_objects(str(lib), str(tmp_path / "out"))
    assert error is not None and "oca_config.h failed" in error
    assert not (tmp_path / "out" / "unit.o").exists()


@pytest.mark.skipif(shutil.which("cc") is None, reason="needs a C compiler")
def test_the_library_builds_with_its_generated_configuration(tmp_path):
    assert equivalence.build_objects(LIB_DIR, str(tmp_path)) is None
    sources = [n for n in os.listdir(LIB_DIR) if n.endswith(".c")]
    built = [n for n in os.listdir(tmp_path) if n.endswith(".o")]
    assert len(built) == len(sources)

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
import subprocess
import sys


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

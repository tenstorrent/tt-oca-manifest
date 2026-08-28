"""Prove a change to the OCA validator library touched only comments.

    python3 validators/oca/lib/scripts/check_object_equivalence.py \
            --baseline <git-ref>

Builds every `lib/*.c` at the baseline ref and in the working tree with
identical flags, then compares the object files byte for byte. Comments do not
reach the compiler's output, so a comment-only change MUST leave every object
identical. One differing object means code changed.

This holds because the library has no `__LINE__`, `__FILE__`, or `assert()`, and
builds `-Os -ffreestanding -nostdlib` with no `-g` — nothing carries source line
numbers into the output, so shifting every line down by ten changes nothing.
Verified before this script was written: inserting a ten-line block into
`payload.c` left all thirteen objects identical.

Why this is not a pytest test
-----------------------------
A legitimate code change SHOULD alter object files. Wired into the default suite
this would fail on the first real commit and be disabled within the week. It
gates comment-only work specifically, run by hand during such a change and cited
in the change description.

The comparison and reporting logic below is deliberately separate from the build
and worktree steps so it can be unit-tested without invoking git or a compiler.

Exit codes: 0 all identical, 1 at least one differs, 2 build or setup failure.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile


LIB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(LIB_DIR)))
LIB_RELATIVE = os.path.relpath(LIB_DIR, REPO_ROOT)

COMPILE_FLAGS = [
    "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic",
    "-ffreestanding", "-nostdlib", "-fno-builtin", "-Os",
]


class ComparisonResult:
    """Outcome of comparing one translation unit's object files."""

    def __init__(self, name, identical, baseline_digest=None, current_digest=None):
        self.name = name
        self.identical = identical
        self.baseline_digest = baseline_digest
        self.current_digest = current_digest


def digest_file(path):
    """SHA-256 of a file's bytes."""
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compare_object_dirs(baseline_dir, current_dir):
    """Compare every .o present in either directory.

    Pure filesystem comparison with no build or git involvement, so it can be
    exercised directly by tests. An object present in one tree and missing from
    the other counts as differing — a source file was added or removed, which is
    not a comment-only change either.
    """
    names = sorted(
        {n for n in os.listdir(baseline_dir) if n.endswith(".o")}
        | {n for n in os.listdir(current_dir) if n.endswith(".o")}
    )
    results = []
    for name in names:
        baseline_path = os.path.join(baseline_dir, name)
        current_path = os.path.join(current_dir, name)
        if not os.path.exists(baseline_path) or not os.path.exists(current_path):
            results.append(ComparisonResult(name, False))
            continue
        baseline_digest = digest_file(baseline_path)
        current_digest = digest_file(current_path)
        results.append(ComparisonResult(
            name, baseline_digest == current_digest, baseline_digest, current_digest))
    return results


def format_report(results, baseline_ref):
    """Render the comparison as the text the operator reads. Pure function."""
    lines = [f"baseline: {baseline_ref}   working tree: current", ""]
    for result in results:
        marker = "IDENTICAL" if result.identical else "DIFFERS  "
        suffix = "" if result.identical else "    <-- code changed, not just comments"
        lines.append(f"  {marker}  {result.name}{suffix}")
    identical = sum(1 for r in results if r.identical)
    total = len(results)
    lines.append("")
    if identical == total and total:
        lines.append(f"{identical}/{total} identical — PASS")
        lines.append("The change provably touched only comments.")
    else:
        lines.append(f"{identical}/{total} identical — FAIL")
        for result in results:
            if not result.identical:
                lines.append(f"{result.name} differs.")
        lines.append(
            "A comment-only change cannot alter object code in this library "
            "(no __LINE__/__FILE__/assert, built -Os without -g). Review the "
            "diff for an accidental code edit.")
    return "\n".join(lines)


def build_objects(source_lib_dir, output_dir):
    """Compile every lib/*.c into output_dir. Returns None, or an error string."""
    os.makedirs(output_dir, exist_ok=True)
    sources = sorted(
        os.path.join(source_lib_dir, n)
        for n in os.listdir(source_lib_dir) if n.endswith(".c")
    )
    if not sources:
        return f"no .c files found in {source_lib_dir}"
    for source in sources:
        target = os.path.join(
            output_dir, os.path.basename(source)[:-2] + ".o")
        command = ["cc"] + COMPILE_FLAGS + ["-I", source_lib_dir,
                                            "-c", source, "-o", target]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            return f"compiling {source} failed:\n{completed.stderr}"
    return None


def materialise_baseline(baseline_ref, worktree_dir):
    """Check out baseline_ref into worktree_dir. Returns None, or an error string."""
    completed = subprocess.run(
        ["git", "worktree", "add", "--detach", worktree_dir, baseline_ref],
        cwd=REPO_ROOT, capture_output=True, text=True)
    if completed.returncode != 0:
        return f"git worktree add failed for {baseline_ref!r}:\n{completed.stderr}"
    return None


def remove_worktree(worktree_dir):
    subprocess.run(["git", "worktree", "remove", "--force", worktree_dir],
                   cwd=REPO_ROOT, capture_output=True, text=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Prove a library change altered no object code.")
    parser.add_argument("--baseline", required=True,
                        help="git ref to compare against (the pre-refactor commit)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temporary worktree and build directories")
    args = parser.parse_args(argv)

    scratch = tempfile.mkdtemp(prefix="oca-objeq-")
    worktree = os.path.join(scratch, "baseline-tree")
    baseline_objects = os.path.join(scratch, "baseline-obj")
    current_objects = os.path.join(scratch, "current-obj")

    try:
        error = materialise_baseline(args.baseline, worktree)
        if error:
            print(f"error: {error}", file=sys.stderr)
            return 2

        error = build_objects(os.path.join(worktree, LIB_RELATIVE), baseline_objects)
        if error:
            print(f"error: baseline build: {error}", file=sys.stderr)
            return 2

        error = build_objects(LIB_DIR, current_objects)
        if error:
            print(f"error: working-tree build: {error}", file=sys.stderr)
            return 2

        results = compare_object_dirs(baseline_objects, current_objects)
        print(format_report(results, args.baseline))
        return 0 if all(r.identical for r in results) else 1
    finally:
        if args.keep:
            print(f"\nkept: {scratch}", file=sys.stderr)
        else:
            remove_worktree(worktree)
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

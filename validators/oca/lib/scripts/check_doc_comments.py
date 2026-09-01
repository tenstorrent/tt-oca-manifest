# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""House-style rules for the OCA validator library's documentation comments.

Run from anywhere in the project tree:

    python3 validators/oca/lib/scripts/check_doc_comments.py [--file PATH]

This script owns only the rules that are properties of the comment text itself
and that no off-the-shelf tool knows about: the `/**` opener, `@` rather than
`\\` for commands, an explicit `@brief`, a long description that adds something
to the brief, and a direction marker on every `@param`. It does no C parsing —
it reads comments, not declarations.

Two other layers own the rest, each better at its half than a regex scanner:

  * `-Wdocumentation` and `-Wdocumentation-unknown-command`, probed into CFLAGS
    by the Makefile, check markup against the declaration it sits on: a
    `@param` naming no such argument, a `@return` on a void function, a
    mistyped `@parm`. Compile time, on every build.
  * `doxygen Doxyfile` discovers the entities. It models C, so it reports the
    undocumented struct, typedef, macro, and file-scope variable a brace-depth
    scanner misses, a parameter left undocumented, and a contract restated in a
    second header.

Result-code claims — whether a documented `@retval` is one the function can
actually produce — are check_retval_docs.py's job.

Exit codes: 0 clean, 1 findings, 2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import doc_blocks


LIB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(LIB_DIR)))

# Layout headers hold only offset macros. Out of scope here, and excluded from
# the Doxyfile for the same reason — keep the two lists in step.
SKIPPED_FILES = frozenset({
    "oca_layout.h",
    "oca_layout_classic.h",
    "oca_layout_pqc.h",
})

# A doc comment opens with one of these. A plain `/*` is an implementation
# note, which these rules have no opinion about; whether something needed a doc
# block and lacks one is doxygen's question, not this script's.
DOC_OPENERS = ("/**", "/*!")

# Commands that make a multi-line block a contract, as opposed to a field or
# constant's description. Nothing here has to work out what the block sits on:
# doxygen already requires a @param per parameter and a documented return, so
# anything with either carries a command by the time it reaches this script.
CONTRACT_COMMANDS = frozenset({"brief", "param", "retval", "return", "file"})


def normalize(sentence):
    return re.sub(r"[^a-z0-9 ]", "", (sentence or "").lower()).strip()


def doc_block_spans(text):
    """Every `/**` or `/*!` comment in the file, as (raw, line)."""
    blocks = []
    for start, end, kind in doc_blocks.find_comment_spans(text):
        if kind != "block":
            continue
        raw = text[start:end]
        if raw.startswith(DOC_OPENERS):
            blocks.append((raw, doc_blocks.line_of(text, start)))
    return blocks


def label_for(block):
    """A short name for the report — the brief, or the block's opening words."""
    if "file" in block.commands:
        return "(file block)"
    subject = " ".join((block.brief or block.description or "").split())
    if len(subject) > 34:
        return subject[:31] + "..."
    return subject or "(block)"


def check_opener(filename, block, findings):
    """The house style is `/**`; doxygen accepts `/*!` and would say nothing."""
    if block.opener != "/**":
        findings.append(doc_blocks.Finding(
            filename, block.line, label_for(block), "bad-opener",
            f"block opens with {block.opener!r}; the house style is /**"))


def check_backslash(filename, block, findings):
    """`\\brief` and `@brief` both work, which is how a file ends up using each
    in half its blocks."""
    if re.search(r"\\(?:brief|param|retval|return|file)\b", block.raw):
        findings.append(doc_blocks.Finding(
            filename, block.line, label_for(block), "backslash-command",
            "uses a \\command; the house style is @"))


def check_brief_and_description(filename, block, findings):
    """A contract needs a title, and something the title does not already say."""
    if not block.brief:
        findings.append(doc_blocks.Finding(
            filename, block.line, label_for(block), "missing-brief",
            "no explicit @brief"))
    # A @file block is exempt from needing more than a brief: for a small
    # translation unit the one-line summary is the whole truth, and demanding a
    # second paragraph would produce exactly the filler the next rule rejects.
    if "file" in block.commands:
        return
    if not block.description:
        findings.append(doc_blocks.Finding(
            filename, block.line, label_for(block), "missing-description",
            "no long description separate from the brief"))
    elif normalize(block.description) == normalize(block.brief):
        findings.append(doc_blocks.Finding(
            filename, block.line, label_for(block), "description-echoes-brief",
            "long description restates the brief instead of adding information"))


def check_param_directions(filename, block, findings):
    """Every `@param` states whether the callee reads it, writes it, or both.

    Doxygen accepts a bare `@param`, and the direction is the part a caller most
    needs: it says whether a buffer is theirs to fill or the library's.
    """
    for name, direction in block.params.items():
        if direction not in ("in", "out", "in,out"):
            findings.append(doc_blocks.Finding(
                filename, block.line, label_for(block), "undirected-param",
                f"@param {name} has no [in]/[out]/[in,out] direction marker"))


def states_a_contract(block):
    """Whether the brief/description pair is owed for this block.

    A one-liner is a value's description — `/**< The first field. */` — and a
    block with no commands at all is prose. Neither is a contract, and holding
    them to a title-plus-long-description rule produces filler, which is what
    description-echoes-brief exists to reject.
    """
    return not block.is_single_line and bool(CONTRACT_COMMANDS & set(block.commands))


def check_block(filename, block, findings):
    """Apply every rule that applies to this block."""
    check_opener(filename, block, findings)
    check_backslash(filename, block, findings)
    check_param_directions(filename, block, findings)
    if states_a_contract(block):
        check_brief_and_description(filename, block, findings)


def check_file(path, findings):
    """Check one C source or header. Returns the number of blocks inspected."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    filename = os.path.relpath(path, PROJECT_ROOT)
    blocks = doc_block_spans(text)
    for raw, line in blocks:
        check_block(filename, doc_blocks.parse_doc_block(raw, line), findings)
    return len(blocks)


def library_files(single=None):
    """Every in-scope file, or just the one requested."""
    if single:
        return [os.path.abspath(single)]
    names = sorted(
        n for n in os.listdir(LIB_DIR)
        if (n.endswith(".h") or n.endswith(".c")) and n not in SKIPPED_FILES
    )
    return [os.path.join(LIB_DIR, n) for n in names]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check house style in the OCA validator library's doc comments.")
    parser.add_argument("--file", help="check a single file instead of the library")
    args = parser.parse_args(argv)

    findings = []
    try:
        paths = library_files(args.file)
        inspected = sum(check_file(path, findings) for path in paths)
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    files_with_findings = doc_blocks.report(findings)
    if findings:
        print(f"{len(findings)} finding(s) across {files_with_findings} file(s); "
              f"{inspected} blocks inspected")
        return 1
    print(f"clean — {inspected} documentation blocks across {len(paths)} files "
          f"follow the house style")
    return 0


if __name__ == "__main__":
    sys.exit(main())

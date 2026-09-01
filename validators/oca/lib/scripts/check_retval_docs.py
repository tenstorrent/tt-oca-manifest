# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Check that documented result codes are ones the function can actually return.

Run from anywhere in the project tree:

    python3 validators/oca/lib/scripts/check_retval_docs.py [--file PATH]

Everything else in this project's documentation tooling checks that a comment is
well FORMED. This script is the only thing that checks whether one is TRUE. It
reads function bodies, works out which result codes each can originate, and
compares that against the block's `@retval` entries in both directions: a code
the body returns with no entry, and an entry naming a code nothing reachable
produces. It caught a documented failure code on a function whose body was
nothing but `return OCA_OK;`.

Deliberately narrow. It parses function bodies and nothing else — no struct
members, no types, no parameter lists — because the rest of the documentation
gate is owned by doxygen and `-Wdocumentation`, which model C properly.
See check_doc_comments.py for the division of labour.

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

SKIPPED_FILES = frozenset({
    "oca_layout.h",
    "oca_layout_classic.h",
    "oca_layout_pqc.h",
})

# C keywords that can precede a parenthesis at statement position. Without this
# the scanner reads `if (x)` and `sizeof (y)` as declarations.
NON_FUNCTION_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "defined",
    "typedef", "else", "do", "_Static_assert", "static_assert",
    "struct", "union", "enum", "case", "goto", "break", "continue",
})

# Anchored at line start, and every internal separator is [ \t] rather than \s.
# With \s the return-type repetition crosses newlines, so a match beginning at a
# depth-0 identifier can run through several declarations — and through blanked
# comments, which are whitespace — before finding a '(' deep inside a struct.
# The recorded start is then depth 0 while the real declarator is not, and the
# scan reports the tail of a type name as a function called "t".
# The separator before the name is MANDATORY — either pointer stars or at least
# one space. Without it the engine backtracks into the return type's own
# identifier, splitting `oca_check_length` into `oca_check_lengt` + a function
# named `h`, which then matches the following '(' quite happily. The return-type
# repetition is lazy so it grows only when a multi-word type demands it.
_DECL_RE = re.compile(
    r"^[ \t]*(?P<store>(?:(?:static|inline|extern)[ \t]+)*)"
    r"(?P<ret>(?:const[ \t]+)?[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*?)"
    r"(?P<sep>[ \t]*\*+[ \t]*|[ \t]+)"
    r"(?P<name>[A-Za-z_]\w*)[ \t]*\(",
    re.M,
)

_RETURN_LITERAL_RE = re.compile(r"\breturn\s+(OCA_[A-Z0-9_]+)\s*;")
_RETURN_ANY_RE = re.compile(r"\breturn\b(?P<expr>[^;]*);")
_ASSIGNED_LITERAL_RE = re.compile(r"(\w+)\s*=\s*(OCA_[A-Z0-9_]+)\s*;")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


class Function:
    """A function declaration or definition, and what its body can produce."""

    def __init__(self, name, file, line, offset, return_type, is_definition):
        self.name = name
        self.file = file
        self.line = line
        self.offset = offset
        self.return_type = return_type
        self.is_definition = is_definition
        self.originated = set()
        self.propagates = False
        self.callees = set()
        self.reachable = set()
        self.block = None


def blank_spans(text, spans):
    """Replace each (start, end) with spaces, preserving newlines and offsets."""
    chars = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def make_code_view(text):
    """Text with comments, strings, and preprocessor lines blanked.

    Also removes `#ifdef __cplusplus` regions wholesale. Those contain only the
    `extern "C" {` / `}` pair, whose opening brace has no matching close inside
    the same region — left in place it sinks an entire public header to brace
    depth 1 and the depth-0 declaration scan finds nothing at all.
    """
    spans = [(s, e) for s, e, _ in doc_blocks.find_comment_spans(text)]
    view = blank_spans(text, spans)

    guard_spans = [
        (m.start(), m.end())
        for m in re.finditer(r"#\s*ifdef\s+__cplusplus.*?#\s*endif", view, re.S)
    ]
    view = blank_spans(view, guard_spans)

    directive_spans = []
    for match in re.finditer(r"^[ \t]*#", view, re.M):
        start = match.start()
        end = start
        while end < len(view):
            newline = view.find("\n", end)
            if newline < 0:
                end = len(view)
                break
            if view[newline - 1:newline] == "\\":
                end = newline + 1
                continue
            end = newline
            break
        directive_spans.append((start, end))
    return blank_spans(view, directive_spans)


def build_depth_map(code):
    """depth[i] = brace nesting depth at offset i; a closing brace reads as its outer depth."""
    depth = 0
    out = []
    for ch in code:
        if ch == "}":
            depth -= 1
        out.append(depth)
        if ch == "{":
            depth += 1
    return out


def match_paren(code, open_index):
    """Offset just past the ')' matching the '(' at open_index, or -1."""
    depth = 0
    for i in range(open_index, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def match_brace(code, open_index):
    """Offset just past the '}' matching the '{' at open_index, or -1."""
    depth = 0
    for i in range(open_index, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def analyse_body(code, body_start):
    """Return (originated, propagates, callees) for the function body at body_start.

    A code counts as originated when it appears as a literal in a `return`, or
    is assigned to a local that is later returned — `return fail_code;` where
    fail_code was set from a literal is origination, not propagation.

    `callees` names the functions called in the body. The caller resolves those
    against the other definitions to fold in what they can produce.
    """
    body_end = match_brace(code, body_start)
    if body_end < 0:
        return set(), False, set()
    body = code[body_start:body_end]

    originated = set(_RETURN_LITERAL_RE.findall(body))
    # Locals assigned a literal code, then returned.
    assigned = dict(_ASSIGNED_LITERAL_RE.findall(body))
    for match in _RETURN_ANY_RE.finditer(body):
        expr = match.group("expr").strip()
        if expr in assigned:
            originated.add(assigned[expr])

    propagates = False
    for match in _RETURN_ANY_RE.finditer(body):
        expr = match.group("expr").strip()
        if not expr or re.fullmatch(r"OCA_[A-Z0-9_]+", expr) or expr in assigned:
            continue
        propagates = True

    callees = set(_CALL_RE.findall(body)) - NON_FUNCTION_KEYWORDS
    return originated, propagates, callees


def extract_functions(text, code, depth, filename):
    """Functions at brace depth 0: declarations, header definitions, and statics."""
    functions = []
    seen = set()
    for match in _DECL_RE.finditer(code):
        start = match.start()
        if depth[start] != 0:
            continue
        name = match.group("name")
        return_type = (match.group("ret") or "").strip()
        first_word = return_type.split()[0] if return_type.split() else ""
        if name in NON_FUNCTION_KEYWORDS or first_word in NON_FUNCTION_KEYWORDS:
            continue
        # Reject a "name" carved out of the tail of an identifier. Backtracking
        # can split `oca_result_t` into ret=`oca_result_` + name=`t`, which then
        # matches the '(' of a function-pointer member.
        name_start = match.start("name")
        if name_start > 0 and (code[name_start - 1].isalnum() or code[name_start - 1] == "_"):
            continue
        open_paren = match.end() - 1
        if depth[open_paren] != 0:
            continue
        after_args = match_paren(code, open_paren)
        if after_args < 0:
            continue
        tail = code[after_args:].lstrip()
        if tail[:1] not in (";", "{"):
            continue
        is_definition = tail[:1] == "{"

        key = (name, is_definition)
        if key in seen:
            continue
        seen.add(key)

        function = Function(
            name=name,
            file=filename,
            line=doc_blocks.line_of(text, start),
            offset=start,
            return_type=return_type,
            is_definition=is_definition,
        )
        if is_definition:
            body_start = code.index("{", after_args - 1)
            function.originated, function.propagates, function.callees = \
                analyse_body(code, body_start)
        functions.append(function)
    return functions


def scan_file(path):
    """Every function in one C source or header, with its doc block attached."""
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    filename = os.path.relpath(path, PROJECT_ROOT)
    code = make_code_view(text)
    functions = extract_functions(text, code, build_depth_map(code), filename)
    for function in functions:
        raw = doc_blocks.preceding_block(text, function.offset)
        function.block = doc_blocks.parse_doc_block(
            raw, doc_blocks.line_of(text, function.offset))
    return functions


def enum_members_by_type():
    """Map each typedef'd enum name to its enumerators.

    Per-type rather than a single oca_result_t set: the hardware callbacks
    return oca_hw_result_t, and validating their @retval entries against the
    result enum would report every correct one as unknown. Keyed by the typedef
    name so a block documenting OCA_HW_OK on an oca_result_t function is still
    caught.
    """
    members = {}
    for name in sorted(os.listdir(LIB_DIR)):
        if not name.endswith(".h") or name in SKIPPED_FILES:
            continue
        with open(os.path.join(LIB_DIR, name), encoding="utf-8") as handle:
            code = make_code_view(handle.read())
        for match in re.finditer(r"typedef\s+enum\s+\w*\s*\{", code):
            body_start = code.index("{", match.start())
            body_end = match_brace(code, body_start)
            if body_end < 0:
                continue
            trailer = re.match(r"\s*(\w+)\s*;", code[body_end:body_end + 120])
            if not trailer:
                continue
            members[trailer.group(1)] = set(
                re.findall(r"\b(OCA_[A-Z0-9_]+)\b", code[body_start:body_end]))
    return members


def collect(paths):
    """Scan every path and give each declaration its definition's behaviour."""
    per_file = {}
    for path in paths:
        per_file[os.path.relpath(path, PROJECT_ROOT)] = scan_file(path)

    definitions = {
        f.name: f
        for functions in per_file.values() for f in functions if f.is_definition
    }

    # Two sets per function, because the two directions of the rule need
    # different notions of "can produce", and conflating them makes one wrong:
    #
    #   originated — what this function's OWN body puts into a return. Used for
    #                the FORWARD check: you must document what you yourself
    #                produce. Narrow on purpose, so a composite entry point is
    #                not required to enumerate all thirty codes. Deliberately
    #                NOT folded across calls — a code a helper produces and this
    #                function hands back is propagation from the documentation's
    #                point of view, covered by the @return summary.
    #
    #   reachable  — everything anywhere in the library's call tree below this
    #                function can produce. Used for the REVERSE check: an
    #                @retval is wrong only if nothing reachable yields it. Broad
    #                on purpose, because a thin public wrapper that delegates to
    #                another translation unit still genuinely returns the
    #                callee's codes, and documenting them is exactly right.
    for function in definitions.values():
        function.reachable = set(function.originated)
    changed = True
    while changed:
        changed = False
        for function in definitions.values():
            for callee_name in function.callees:
                callee = definitions.get(callee_name)
                if callee is None or callee is function:
                    continue
                if not callee.reachable <= function.reachable:
                    function.reachable |= callee.reachable
                    changed = True

    # A header declaration carries the documentation, but the return behaviour
    # it must describe lives in the definition.
    for functions in per_file.values():
        for function in functions:
            if not function.is_definition and function.name in definitions:
                source = definitions[function.name]
                function.originated = source.originated
                function.reachable = source.reachable
                function.propagates = source.propagates
    return per_file


def check_function(function, findings, enum_members):
    """Compare one documented function's @retval entries against its body."""
    block = function.block
    if block is None or block.opener == "/*":
        return
    if not block.retvals and not block.ret:
        return

    return_key = (function.return_type or "").replace("const", "").strip()
    result_codes = enum_members.get(return_key, set())
    if not result_codes:
        return

    # Origination is collected by pattern-matching OCA_* identifiers in return
    # and assignment position, which also picks up layout-offset macros and
    # codes from a different enum. Intersecting with the enum this function
    # actually returns is what makes the set meaningful.
    originated = function.originated & result_codes
    reachable = function.reachable & result_codes

    for code in block.retvals:
        if code.startswith("OCA_") and code not in result_codes:
            findings.append(doc_blocks.Finding(
                function.file, block.line, function.name, "retval-unknown-code",
                f"@retval {code} is not a member of {return_key}"))

    if not originated and not function.propagates:
        return

    # The reverse check — "this @retval names a code the function cannot
    # produce" — is only sound when the body is FULLY understood, meaning every
    # return is a literal. A propagating function hands back codes through
    # variables, out-parameters (`oca_variant_for_body(body, &status); ...
    # return status;`) and cross-translation-unit calls, none of which this
    # analysis follows. Firing there would flag correct documentation, which is
    # worse than not firing at all: a checker that cries wolf on good work
    # teaches people to ignore it.
    #
    # Restricted this way it still catches the case that matters — a documented
    # failure code on a function whose body is nothing but `return OCA_OK;`.
    if not function.propagates:
        for code in block.retvals:
            if code.startswith("OCA_") and code in result_codes and code not in reachable:
                findings.append(doc_blocks.Finding(
                    function.file, block.line, function.name, "retval-not-originated",
                    f"@retval {code} — nothing reachable from this function "
                    f"can produce it"))

    for code in sorted(originated):
        if code not in block.retvals:
            findings.append(doc_blocks.Finding(
                function.file, block.line, function.name, "originated-undocumented",
                f"returns {code} but has no @retval for it"))

    if function.propagates and not block.ret:
        findings.append(doc_blocks.Finding(
            function.file, block.line, function.name, "propagation-missing-return",
            "propagates results from calls it composes but has no @return "
            "summary; @retval entries alone cannot describe them"))


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
        description="Check @retval claims against what the OCA validator's bodies return.")
    parser.add_argument("--file", help="check a single file instead of the library")
    args = parser.parse_args(argv)

    try:
        per_file = collect(library_files(args.file))
        enum_members = enum_members_by_type()
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    findings = []
    for functions in per_file.values():
        for function in functions:
            check_function(function, findings, enum_members)

    checked = sum(len(functions) for functions in per_file.values())
    files_with_findings = doc_blocks.report(findings)
    if findings:
        print(f"{len(findings)} finding(s) across {files_with_findings} file(s); "
              f"{checked} functions scanned")
        return 1
    print(f"clean — the documented result codes of {checked} functions across "
          f"{len(per_file)} files match what their bodies return")
    return 0


if __name__ == "__main__":
    sys.exit(main())

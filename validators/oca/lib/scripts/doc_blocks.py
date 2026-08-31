# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Locating and parsing `/** ... */` comments, shared by the two doc gates.

check_doc_comments.py reads these blocks for house style and check_retval_docs.py
reads them for result-code claims. Parsing them twice is how the two gates would
come to disagree about what a block says, so the parser lives here and neither
script keeps a copy.
"""

from __future__ import annotations

import re


# Inline markup, as opposed to block-level section commands. These appear inside
# running prose and must not be read as starting a new section: `@p`, `@c` and
# friends routinely open a line, and treating one as a section header swallows
# the long description and then reports it missing.
INLINE_COMMANDS = frozenset({"p", "c", "a", "b", "ref"})


class Finding:
    """One rule violation, in the shape the report prints."""

    def __init__(self, file, line, entity, rule, detail):
        self.file = file
        self.line = line
        self.entity = entity
        self.rule = rule
        self.detail = detail

    def __repr__(self):
        return f"{self.file}:{self.line} {self.entity} [{self.rule}] {self.detail}"


class DocBlock:
    """A parsed `/** ... */` comment."""

    def __init__(self, opener, brief, description, params, retvals, ret,
                 commands, raw, line):
        self.opener = opener
        self.brief = brief
        self.description = description
        self.params = params          # name -> direction ("in"/"out"/"in,out"/None)
        self.retvals = retvals        # code -> description
        self.ret = ret
        self.commands = commands
        self.raw = raw
        self.line = line

    @property
    def is_single_line(self):
        """Whether the whole block was written on one line.

        `/**< The first field. */` and `/** @brief Eight bytes. */` are short
        descriptions of a value, not contracts, and reading them as contracts is
        how a rule demanding a long description turns into a rule demanding
        filler.
        """
        return "\n" not in self.raw


def find_comment_spans(text):
    """Locate every comment and string literal as (start, end, kind)."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            spans.append((i, j, "block"))
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            spans.append((i, j, "line"))
            i = j
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            spans.append((i, j, "string"))
            i = j
        else:
            i += 1
    return spans


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def preceding_block(text, offset):
    """The comment block immediately above `offset`, if any.

    Also recognizes a trailing `/**< ... */` on the same line, which is the
    accepted form for short struct-field and enumerator descriptions.
    """
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    line_end = len(text) if line_end < 0 else line_end
    trailing = re.search(r"/\*\*<(.*?)\*/", text[offset:line_end], re.S)
    if trailing:
        return text[offset + trailing.start():offset + trailing.end()]

    probe = line_start - 1
    while probe > 0 and text[probe] in " \t\n":
        probe -= 1
    if probe <= 0 or text[probe] != "/" or text[probe - 1] != "*":
        return None
    end = probe + 1
    start = text.rfind("/*", 0, end)
    if start < 0:
        return None
    # A comment with code before it on its own line is a TRAILING comment
    # belonging to that line, not a block introducing this entity.
    comment_line_start = text.rfind("\n", 0, start) + 1
    if text[comment_line_start:start].strip():
        return None
    return text[start:end]


def parse_doc_block(raw, line):
    """Parse a raw comment into a DocBlock, or None if there is nothing to parse."""
    if raw is None:
        return None
    opener = "/**" if raw.startswith("/**") else ("/*!" if raw.startswith("/*!") else "/*")
    body = raw
    for prefix in ("/**<", "/*!<", "/**", "/*!", "/*"):
        if body.startswith(prefix):
            body = body[len(prefix):]
            break
    if body.endswith("*/"):
        body = body[:-2]

    lines = [re.sub(r"^\s*\*(?!/)\s?", "", line_text).strip()
             for line_text in body.splitlines()]

    commands = re.findall(r"[@\\](\w+)", body)
    params, retvals = {}, {}
    brief_parts, description_parts, ret_parts = [], [], []
    mode = "pre"
    for line_text in lines:
        brief_match = re.match(r"[@\\]brief\s*(.*)", line_text)
        param_match = re.match(r"[@\\]param\s*(?:\[([^\]]*)\])?\s*(\w+)?\s*(.*)", line_text)
        retval_match = re.match(r"[@\\]retval\s+(\S+)\s*(.*)", line_text)
        return_match = re.match(r"[@\\]return[s]?\s*(.*)", line_text)
        if brief_match:
            mode = "brief"
            brief_parts.append(brief_match.group(1))
            continue
        if param_match and line_text.lstrip().startswith(("@param", "\\param")):
            mode = "param"
            params[param_match.group(2) or ""] = param_match.group(1)
            continue
        if retval_match:
            mode = "retval"
            retvals[retval_match.group(1)] = retval_match.group(2)
            continue
        if return_match:
            mode = "return"
            ret_parts.append(return_match.group(1))
            continue
        other_command = re.match(r"[@\\](\w+)", line_text)
        if other_command and other_command.group(1) not in INLINE_COMMANDS:
            mode = "other"
            continue
        if mode == "brief":
            if line_text:
                brief_parts.append(line_text)
            else:
                mode = "description"
            continue
        if mode in ("pre", "description"):
            mode = "description"
            description_parts.append(line_text)
            continue
        if mode == "return" and line_text:
            ret_parts.append(line_text)

    return DocBlock(
        opener=opener,
        brief=" ".join(p for p in brief_parts if p).strip() or None,
        description="\n".join(description_parts).strip(),
        params=params,
        retvals=retvals,
        ret=" ".join(p for p in ret_parts if p).strip() or None,
        commands=commands,
        raw=raw,
        line=line,
    )


def report(findings):
    """Print findings grouped by file, in source order."""
    by_file = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)
    for name in sorted(by_file):
        print(name)
        for finding in sorted(by_file[name], key=lambda f: (f.line, f.rule)):
            location = f"L{finding.line}" if finding.line else "--"
            print(f"  {location:<6} {finding.entity:<34} {finding.rule}")
            print(f"         {finding.detail}")
        print()
    return len(by_file)

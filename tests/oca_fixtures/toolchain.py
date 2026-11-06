# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The host compilers the tests build C and C++ with.

`CC` and `CXX` choose them, as they do for make, so the suite runs under gcc
and clang alike. Either may carry arguments, such as `ccache gcc`. Each must
build programs for the machine running the tests, because the tests run what
they build.
"""

from __future__ import annotations

import os
import shlex


def compiler_from_environment(variable: str, default: str) -> list[str]:
    """The command `variable` names, split into words, or `default`."""
    return shlex.split(os.environ.get(variable) or default)


C_COMPILER = compiler_from_environment("CC", "cc")
CXX_COMPILER = compiler_from_environment("CXX", "c++")

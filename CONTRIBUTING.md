# Contributing to tt-oca-manifest

Thank you for your interest in contributing. This document covers how to report
problems, how to submit changes, and the checks a change is expected to pass
before it is merged.

All participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting bugs

Report bugs through [GitHub Issues](https://github.com/tenstorrent/tt-oca-manifest/issues).

A useful report includes the manifest variant involved (`oca-classic` or
`oca-pqc`), the YAML configuration or a reduced version of it, the exact command
you ran, and the output you got against the output you expected. If the problem
is in the C validator, include your compiler and version, since the library is
built against both GCC and Clang.

**Do not report security vulnerabilities through GitHub Issues.** See
[SECURITY.md](SECURITY.md) for the private disclosure process.

## Submitting changes

Bug fixes and new functionality are submitted as Pull Requests. Fork the
repository or push a branch, open a PR against `main`, and describe what the
change does and why.

Pull requests are **reviewed weekly**. A PR needs at least one approving review
before it can be merged, and merges are squashed.

If you are planning a substantial change — a new manifest field, a change to the
on-disk layout, or anything that alters validation semantics — open an issue
first so the design can be discussed before you invest in an implementation. The
manifest format is a published specification that silicon is written against, so
layout changes carry consequences well beyond this repository.

The specification itself is owned by the Open Chiplet Atlas project and published
at <https://www.openchipletatlas.org/specifications/oca/latest>; it is not
maintained here. A change to the format goes to that project first, and this
repository follows it.

## Development setup

The prerequisites are listed in the [README](README.md#prerequisites): Python
3.9+ for the producer, and additionally a C99 toolchain, OpenSSL 3 development
headers, and `pkg-config` to build and test the C validator. Install the package
in editable mode with the test extras:

```bash
pip install -e ".[dev,aws]"
```

The `aws` extra is required even if you do not use AWS KMS signing, because
`tests/test_manifest_signing.py` imports `botocore` at module scope and
collection fails without it.

## Checks your change must pass

Run both suites locally before opening a PR. CI runs the same ones across Python
3.9 and 3.12 and against both GCC and Clang.

```bash
python -m pytest -m "not aws"     # producer + consumer test suites
make -C validators/oca check      # C unit tests and the fixture sweep
```

The AWS KMS tests are deselected rather than skipped; they need live credentials
and are not expected to run in a normal contribution.

Be aware that several tests are gates rather than ordinary unit tests, and they
will fail a change that is otherwise functionally correct:

- **`tests/test_oca_c_validator_layout_sync.py`** fails on any drift between the
  Python producer's layout and the C consumer's headers. If you change one side
  of the manifest layout, you must change the other.
- **`tests/test_oca_c_doxygen.py`**, **`test_oca_c_doc_comments.py`**, and
  **`test_oca_c_retval_docs.py`** require every public C entity to carry a
  complete Doxygen comment, including `@param` and `@return` blocks. New or
  changed C functions need documentation, not just code.
- **`tests/test_oca_c_object_equivalence.py`** checks that documentation changes
  did not alter generated code.

These tests **skip** rather than fail when `make`, `pkg-config`, or `doxygen` is
missing, so a green local run with an incomplete toolchain is not proof. CI
installs all of them and asserts they are present, so the gates always run there.

## Coding standards

- **SPDX headers are required on every new file.** Use
  `SPDX-License-Identifier: Apache-2.0` and
  `SPDX-FileCopyrightText: <year> Tenstorrent USA, Inc.` for code, and
  `SPDX-License-Identifier: CC-BY-4.0` for documentation and images. Match the
  two-line style of the surrounding files.
- **C code** targets C99 and is compiled freestanding to prove it ports to a
  boot ROM. Do not introduce libc dependencies into `validators/oca/lib/`.
- **Python code** supports 3.9 as its floor. Do not use syntax or standard
  library APIs newer than that.
- Match the conventions of the file you are editing — the existing comment
  density and naming are deliberate, particularly in the validator library.

## Commit messages

Write a short imperative subject line describing the change. Where the change is
scoped to one area, the existing history uses a bracketed prefix, for example
`[validator] Secure Boot Handling Logic Improvements`. Explain *why* in the body
when the reason is not obvious from the diff.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0 for code, and the Creative Commons Attribution 4.0
International license for documentation and images. See [LICENSE](LICENSE),
[LICENSE-DOCS](LICENSE-DOCS), and
[LICENSE_understanding.txt](LICENSE_understanding.txt).

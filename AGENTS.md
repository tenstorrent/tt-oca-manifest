# Agent Guide for tt-oca-manifest

This guide helps AI agents navigate and work with the Tenstorrent OCA boot manifest
repository — the Python **producer** that packs, signs and encrypts boot bundles, and the
freestanding C **validator** that reads them back the way silicon does. It covers both
audiences: someone integrating the packer or the validator library into their own project, and
someone changing the code and needing to know which gates must be green before the change is
real.

Machine- and site-specific values are left as placeholders; substitute your own.

## Editing this guide

A guide that is confidently wrong costs more than one that is silent, because a reader has no
reason to doubt it. Three rules keep it worth trusting.

- **Keep it current with the repository.** Any change that materially affects what is written
  here — a renamed target, a moved directory, a new gate, a fixed failure mode — should update
  this file in the same pull request. Verify claims against the tree rather than from memory,
  and prefer pointing at the authoritative file over restating it, since a pointer cannot
  drift.
- **Keep key material and secrets out.** No private keys, no key digests, no production
  signing endpoints, no HSM or KMS identifiers. The development keys under
  `tests/signing_keys/` may be named as what they are — non-production test material — and
  nothing else about signing infrastructure belongs here.
- **Keep it generic and self-contained.** No personal paths, hostnames, usernames, or one-off
  workarounds, and no references to internal planning or process directories. This file ships
  to people integrating the package who receive neither. Write so the guidance still holds for
  someone with a bare clone and no site tooling.

## Read the repository documentation first

This repo documents itself heavily, and nearly every question below is answered somewhere in
it at more depth than this guide can carry. Read these files properly rather than grepping
them for keywords — a partial read costs far more time than a full one.

| Document | What it answers |
|---|---|
| `README.md` | The manifest variants, installation, packing, YAML config field reference, signing authorities, secure boot, test organization |
| `validators/oca/README.md` | Validator layout, build targets, compile-time gates, the producer/consumer lock-step gates and what to do when you add a field |
| `validators/oca/INTEGRATION.md` | Building a consumer on the library: vendoring, the callback table, entry points, the staged boot flow, reaching the plaintext payload, walking the TOC, secure-boot device state |
| [OCA boot manifest specification](https://www.openchipletatlas.org/specifications/oca/latest) | The format specification itself — the authority the producer and validator both implement. Owned and published by the Open Chiplet Atlas project, not maintained in this repository |
| `validators/oca/lib/oca_validator.h` | The sole public C header; the API contract and every result code |
| `src/oca/constants.py` | OCA offsets, lengths and enums — the **source of truth** the C layout headers mirror |
| `configs/*.yaml` | Worked configs, one per feature area: classic, PQC, encrypted, secure-boot device state, control-plane, and combined — plus `oca_production_template.yaml`, the starting point for a real build, which deliberately does not build from a clean checkout |
| `examples/oca_classic_basic/` | A runnable end-to-end example: config, image, pack and verify |
| `.github/workflows/ci.yml` | The exact commands CI runs and, in unusually good comments, why each guard exists |

## The first thing to get right: two variants and a packaging mode

Everything this repo emits is OCA (Open Chiplet Atlas), a fixed-layout manifest body followed
by a `PTOC`-prefixed payload table-of-contents. The `manifest_format` field at the top of the
YAML config takes **three** values, and the fact that only two of them are formats is the most
common way to reason about this repo incorrectly.

- **`oca-classic`** (magic `OCAC`, 4096-byte body) and **`oca-pqc`** (magic `OCAP`,
  36864-byte body) are the two on-disk variants. PQC is a **superset** of the Classic layout,
  not a sibling exception to it.
- **`oca-combined`** is a **packaging mode, not a manifest format.** It assembles one or more
  already-built manifest+payload combos — software banks — plus optional opaque auxiliary
  regions into a single flat image at caller-chosen offsets. Each combo is produced by the
  ordinary bundle generator and left byte-for-byte unchanged except for its *unsigned*
  `payload_offset`, which is reconciled to the payload's placed location. No signing happens
  there; each referenced config owns its own. The configuration is the authoritative map of
  the image — no header or index is embedded in the output.

There is no default: `manifest_format` is required, and an unknown value is rejected with the
allowed list.

**The C validator is format-agnostic.** One library and one binary handle every OCA variant;
the format-specific dispatch happens inside the library on the manifest magic bytes.
Integrators never select a variant when calling it. Do not describe it as "the OCA-Classic
validator" — Classic is simply the variant implemented most completely today, and PQC and
future variants slot in under `lib/` without a build-system fork.

## Repository Structure

| Path | Contents |
|---|---|
| `src/` | The `tt_boot_manifest` package. `pack_images.py` is the CLI entry point and format dispatch; `manifest_signing.py`, `aes*.py` and `utils.py` are the shared signing, encryption and config-loading layers |
| `src/oca/` | The OCA producer: `entry.py` (`pack_oca_bundle`), `constants.py` (layout source of truth), `validators.py` (config validation), `combined.py` (multi-bank assembly), plus manifest/TOC/payload/encryption/constraint builders |
| `src/manifest_signing.py` | The signing abstraction — `local`, `aws`, `hsm` — that every signing operation goes through |
| `validators/oca/lib/` | The freestanding C validator library. **This is the directory a target firmware project vendors** |
| `validators/oca/lib/scripts/` | The drift and documentation checkers pytest drives: `sync_layout.py`, `check_doc_comments.py`, `check_retval_docs.py`, `check_object_equivalence.py` |
| `validators/oca/test/` | Host harness — the `oca-validate` CLI, the in-tree C unit tests, and the fixture configs. **Never shipped to silicon** |
| `tests/` | The pytest suite: OCA producer, signing, and the C-validator integration and drift gates |
| `tests/signing_keys/` | Development test keys **only**. Never production |
| `tools/` | `aws_sso.py`, the `aws-sso` console script |
| `configs/` | Example YAML configs, one per feature area |
| `out/` | Default output directory for packed bundles; git-ignored |

## Environment Setup

### Python

Python 3.9 or newer. Install the package **editable** into whichever Python environment you
already use, with both extras:

```bash
pip install -e '.[dev,aws]'
```

The `aws` extra is required even when you never touch AWS: `tests/test_manifest_signing.py`
imports botocore at module scope, so collection fails outright without it. `dev` alone cannot
run the suite.

Tests import the *installed* package (`from tt_boot_manifest.oca import ...`), while sources
inside `src/` use relative imports. An editable install keeps source edits live; a newly added
module or console script still needs a reinstall.

Note that the distribution is named `tt-oca-manifest` while the import package remains
`tt_boot_manifest`, so existing `python -m tt_boot_manifest.pack_images` workflows are a
drop-in.

### C validator

Needed to build the validator and to run the validator integration tests, which **skip**
rather than fail when it is absent:

- A host C toolchain with `-std=c99` support (gcc 12+ or clang 16+)
- OpenSSL 3 development headers, discovered via `pkg-config`
  (macOS: `brew install openssl@3`; Debian/Ubuntu: `apt install libssl-dev pkg-config`)
- `doxygen` for the documentation gate — any current release **except 1.9.8**, which falsely
  reports documented functions as undocumented. The test detects that defect and skips with an
  explanation; CI pins 1.18.0

The validator's `make check` needs a Python interpreter that can import `tt_boot_manifest`,
because the fixture sweep packs each fixture with the real producer. The Makefile searches
`$PYTHON`, a repo-local `.venv/` or `venv/`, `$VIRTUAL_ENV`, then `python`/`python3`. If none
of those can import the packer it fails with a clear message. Point it at yours explicitly
when the search order does not find the right one:

```bash
make -C validators/oca PYTHON=<path to interpreter> check
```

## Using the packer

### Packing a bundle

One entry point for every format; the config decides which.

```bash
python -m tt_boot_manifest.pack_images \
    --config configs/oca_classic_example.yaml \
    --out out/oca_classic.bin \
    -v
```

```python
from tt_boot_manifest.pack_images import pack_images

pack_images(config_path="configs/oca_pqc_example.yaml", output_path="out/oca_pqc.bin",
            verbose=True)
```

`python -m tt_boot_manifest.pack_images` is the canonical interface. Ad-hoc top-level scripts
under `src/` are tolerated as utilities but must not become the primary interface for new
features.

`oca-validate` (below) is how you read a packed bundle back and check it.

### Signing

Every signing operation goes through `src/manifest_signing.py` with
`signing_authority ∈ {local, aws, hsm}`. Direct use of raw private keys outside that layer is
forbidden. AWS KMS is the only remote authority currently supported; `hsm` is a reserved slot
and partial implementations must not ship.

**Production manifests are expected to sign through `aws` or `hsm`, not `local`.** A private
key in a PEM file is exposed to every process on the build host, to backups, and to whatever
the build system logs. Treat `local` as a development affordance.

The keys under `tests/signing_keys/` are committed development material and must never sign
anything shipped. `configs/oca_production_template.yaml` is the starting point for a real
secure-boot build.

The packer enforces this. It refuses to sign with any committed key unless the config declares
`allow_test_signing_key: true`, and it matches on the key material, not the path, so a renamed
copy is still refused (`src/key_hygiene.py`). Every config or documentation snippet that signs
with a development key needs that line, and the production template must never carry it.
`tests/conftest.py` sets the equivalent environment override for the whole suite, so a test of
the guard, or of a config or snippet a reader will run, must remove it first; otherwise the
test passes for a reason the reader does not have.

Key material, IVs, plaintext payloads of encrypted sections, and signature internals must
never be written to logs at any verbosity level.

## Using the OCA validator

### Build and run

```bash
make -C validators/oca            # build test/oca-validate (default)
make -C validators/oca lib        # the host static archive only
make -C validators/oca unit_test  # build and run the in-tree C unit tests
make -C validators/oca check      # unit tests + packer-fixture round-trip sweep
make -C validators/oca clean
```

The library compiles `-std=c99 -Wall -Wextra -Werror -pedantic -ffreestanding -nostdlib` to
prove target portability; the archive is for the host CLI and CI, not a release artifact. The
CLI links OpenSSL 3.

```bash
validators/oca/build/test/oca-validate --manifest out/oca_classic.bin --list-images
validators/oca/build/test/oca-validate --help
```

Exit codes are 0 = PASS, 1 = FAIL, 2 = usage error. `--help` is the authority on the hardware
identity, lifecycle, version, payload-secret, root-key and storage-image flags — read it
rather than guessing. Fixture configs under `validators/oca/test/fixtures/configs/` pair each
`<name>.yaml` with a `<name>.flags` file holding the CLI flags that fixture needs.

### Compile-time gates

`EXTRA_CFLAGS` is the single hook for feature gates:

```bash
make -C validators/oca EXTRA_CFLAGS="-DOCA_TOC_MAX_IMAGES=32" test
```

A consumer that must **never** accept a variant compiles the other out. `classic-only` builds
with `-DOCA_SUPPORT_PQC=0`, `pqc-only` with `-DOCA_SUPPORT_CLASSIC=0`, and `both` (identical
to the default) accepts everything; each lands in its own build directory. An excluded variant
is then reported as an unsupported-variant failure rather than validated. This is the only
build-time variant choice — there is no per-variant source fork, and all three configurations
must keep building.

Changing `EXTRA_CFLAGS` does force a rebuild. Make decides what to recompile from timestamps,
never from the last command line, so the Makefile records the flags in a stamp file
(`build/lib/.cflags`) that every object depends on. That stamp is rewritten only when the
flags actually differ, so unchanged builds stay incremental. Without it, a changed gate
silently reuses objects compiled with the previous value — which has produced wrong test
verdicts before.

### Integrating the library

Vendor `validators/oca/lib/` — and only that directory — into the target firmware project.
`test/` is host harness and must never reach silicon. `INTEGRATION.md` is the authority on the
callback table, entry points and the staged flow; two layering rules are worth stating here
because they are easy to get backwards:

- **A crypto callback is pure crypto.** The decryption stub receives a secret *value* and does
  the cipher operation. It does not resolve selectors and does not police invariants.
- **The library enforces the common invariants** — AES block alignment, block modes only — so
  every consumer gets them without reimplementing them.
- **The ingesting application resolves index selectors.** `shared_secret_select` (which starts
  at 1) is resolved to a concrete secret by the integrator before crypto is invoked.

## House rules

These are the standing rules for changes to this repository. They supersede ad-hoc
conventions and individual preference: when a principle conflicts with a convenient
implementation, the principle wins and the convenient implementation is the bug.

### Cryptographic correctness (non-negotiable)

All primitives — RSA-3072 PKCS#1 v1.5, ECDSA P-256 with RFC 6979 deterministic signing,
SHA-256, AES-128-CBC / AES-256-CBC, KBKDF — are invoked exclusively through the `cryptography`
library or a vetted equivalent such as AWS KMS. No hand-rolled crypto, no ad-hoc constant-time
routines, no experimental algorithm choices.

Supported signature algorithms are exactly RSA-3072 PKCS#1 v1.5 + SHA-256
(`signature_type: 0x01`) and ECDSA P-256 + SHA-256 (`signature_type: 0x05`). The specification
defines more values; the packer rejects them at config-load time. Adding another requires both
boot ROM support and a deliberate amendment to these rules — neither alone is sufficient.
Encryption, when enabled, is AES-CBC with KBKDF-derived keys, either 128- or 256-bit per the
manifest's `encryption_type`; mode, key length and KDF parameters including the input-block
construction must match the boot ROM's expectations.

Algorithm and parameter selection is bounded by what the boot ROM accepts, not by what is
theoretically secure. Any deviation is rejected at config-load time with a precise error
naming the offending field.

### Deterministic and reproducible output

Identical inputs must produce byte-identical output. Non-deterministic inputs — timestamps,
IVs, salts, non-deterministic signature schemes — either default to a stable value or are
supplied explicitly by the caller. They must not silently vary between runs. ECDSA uses RFC
6979 specifically to preserve this; the rest of the pipeline holds the same line.

Release artifacts are audited, re-signed and diffed against rebuilds. A field that varies run
to run destroys that.

### Boot ROM format stability

The on-disk layout, field encoding and signature-block positioning are a contract with the
boot ROM and with public-key digests **burned into silicon**. A layout change that shifts the
signed region invalidates every shipped device's trust anchor, and the cost of an accidental
break is unrecoverable.

Changes to the layout or the digest computation are breaking: bump the package version (while
the package is 0.x, a breaking change bumps the MINOR) and update the layout constants in a
single atomic change. Adding optional fields in reserved or padded regions is permitted
provided existing parsers ignore them. There is no `CHANGELOG.md` in this repository and none
should be created.

Before merging anything that alters generated bytes for an existing config, regenerate from
the `configs/oca_*.yaml` examples, diff the binary output, and put the diff — or its absence —
in the pull request description.

### Test-first for security-critical logic (non-negotiable)

Changes to signing, signature verification, encryption, key derivation, or manifest binary
layout ship with tests that **fail before the change and pass after**, covering the positive
path (valid signature accepted, ciphertext round-trips) and the negative path (tampered
manifest rejected, wrong key rejected, malformed input rejected).

Cryptographic regressions are silent: a broken signature check still "works" in the happy
path. Negative-path tests are the only thing that catches a weakened verification routine.

### Comprehensive automated coverage

Every new feature and every refactor ships with tests that meaningfully exercise it — positive
behaviour **and** the negative or error path wherever one can exist. Concretely:

- **Per unit**: representative valid inputs asserting the expected result, and invalid or
  boundary inputs asserting the expected rejection. A happy-path-only test does not satisfy
  this.
- **Error paths**: when a unit calls code that returns specific error codes or raises specific
  exceptions, each case that unit can surface is exercised — not merely the success return.
- **Integration**: manifest assembly, payload/TOC assembly, and end-to-end validation of
  complete manifests, both accepted and rejected.
- **Negative-fixture tooling**: when a negative path needs an artifact the normal builders
  cannot produce — invalid, corrupt, truncated, deliberately unparseable — build the
  generating tooling and use it in the test flow rather than skipping the case. The existing
  checker tests do exactly this, generating malformed C in `tmp_path` to prove each rule still
  fires.

General refactors, CLI ergonomics and non-security helpers may skip the test-first *ordering*,
but they are still bound by this coverage floor. Documentation-only changes are exempt.

"Wherever possible" is a ceiling, not an escape hatch. This project builds exact binary
artifacts with a deterministic producer and a freestanding, callback-injected validator, so a
genuinely untestable code path should be extraordinary — and any claim that one exists must be
justified in the change description.

**Build gates that fail on drift, not checklists reviewers can skip.** Every producer/consumer
and documentation invariant in this repo is enforced by a test for exactly this reason.

### Shipped-artifact hygiene

Distributed artifacts — `src/`, `tools/`, `validators/`, `tests/`, `examples/`, `configs/`,
and all consumer-facing documentation including every `README.md` and this file — must be
free of internal development-process vocabulary and must not reference internal planning
directories. Consumers receive the package without them, so such a
reference is a dangling pointer to a document they will never see and leaks a vocabulary that
is meaningless to an integrator.

Anything a consumer needs lives in the appropriate `README.md`, written for a general audience
and standing alone. Cross-references to internal planning belong in commit messages and pull
request descriptions.

### Review

Changes touching `src/manifest_signing.py`, `src/pack_images.py`, `src/aes128cbc.py`,
`src/aes256cbc.py`, `src/pack_images_constants.py`, `src/oca/`, or `validators/oca/lib/`
require review by someone other than the author before merge.

### Dependencies

New runtime dependencies require justification. The runtime set is deliberately two packages —
`cryptography` and `ruamel.yaml` — and `boto3` only under the `aws` extra. Prefer extending
those over adding a package.

## Producer/consumer lock-step

The Python packer and the C validator must agree byte-for-byte on the manifest layout. That is
enforced by tests that run on every `pytest` invocation, not by review.

**The drift gate.** `tests/test_oca_c_validator_layout_sync.py` runs
`validators/oca/lib/scripts/sync_layout.py`, comparing every offset, length and mask in the C
layout headers against its counterpart in `tt_boot_manifest.oca.constants`. A mismatch fails
with a unified diff and a `sed` fixup suggestion.

**The completeness gate.** The same script enumerates every `OFF_*` / `LEN_*` constant on the
Python side and requires each to be either mapped to a C mirror in `MAPPING` or listed in the
`NOT_REQUIRED_*` allowlist with a one-line rationale. You cannot add a manifest field in
Python and silently leave the validator behind.

**The enum gate.** `tests/test_oca_encoding_enum_sync.py` pins the C `oca_encoding_t`
enumerator values to the packer's on-disk encoding bytes, because `oca_signature_check()`
casts those bytes straight to the enum with no translation. This gate exists because the
failure it prevents actually happened.

### Adding a manifest field

1. Add `OFF_FOO` / `LEN_FOO` to `src/oca/constants.py`.
2. Run `pytest tests/test_oca_c_validator_layout_sync.py`. It fails: `OFF_FOO ... not mapped
   to the C side`.
3. Then either:
   - **Validator-relevant**: add the mirror to the right layout header (see the header split
     below) and an entry to `MAPPING` in `sync_layout.py`. If the field is constraint-bearing,
     write the per-field decoder under `lib/` and compose it into `oca_validate_manifest()`
     for a manifest-level check or `oca_check_payload()` for a payload one — **not** into
     `oca_validate()`, which would leave the staged flow skipping it. Compose cheap checks
     before the signature: a manifest that cannot boot should cost as little as possible to
     reject. If the check applies only under secure boot, take an
     `oca_validation_context_t *` and open with `oca_secure_boot_confirm()` rather than
     deriving the answer yourself. Add a fixture under `test/fixtures/configs/` and a matching
     integration test.
   - **Not validator-relevant**: add the symbol to `NOT_REQUIRED_PREFIXES` in
     `sync_layout.py` with a one-line "why this is OK" comment.
4. `make -C validators/oca check` and `pytest -m "not aws"` both pass → land it.

### The layout header split

`lib/oca_layout.h` holds the offsets, sizes and masks **shared** by every variant, under
neutral `OCA_OFF_*` / `OCA_LEN_*` names. `lib/oca_layout_classic.h` and
`lib/oca_layout_pqc.h` are thin headers carrying only what is variant-specific — fields
present in one variant, or whose offset moves between them. PQC is a superset of Classic, and
this split makes that relationship explicit. Do not treat Classic as the base with PQC as a
sibling exception.

## Documentation gates for the C library

The validator's doc comments are checked by four layers, each catching what the others cannot.
Understand which one is complaining before trying to fix a failure.

| Layer | Runs | Catches |
|---|---|---|
| `-Wdocumentation` | Every clang build, via a Makefile probe | Markup against the declaration it sits on: a `@param` naming no such argument, a `@return` on a `void` function, a mistyped `@parm`. Clang-only; a gcc build simply does not get it |
| doxygen (`tests/test_oca_c_doxygen.py`) | pytest | Entity discovery — a bare struct, a forward typedef, a macro, a file-scope variable carrying no documentation, and contracts restated in a second header |
| `check_doc_comments.py` (`tests/test_oca_c_doc_comments.py`) | pytest | House style, which no tool can know |
| `check_retval_docs.py` (`tests/test_oca_c_retval_docs.py`) | pytest | Whether documented result codes match what the function actually returns — the only check here that asks if a comment is *true* rather than well-formed |

`check_object_equivalence.py` is the separate gate proving a comment-only change altered no
object code. Each checker has its own unit tests driving synthetic inputs, because a checker
that silently stopped recognising a rule would report a clean library forever.

## The test bench

Run all of it before claiming a change works. A bare clone is green with no setup beyond the
Python install and the C toolchain.

```bash
# 1. The Python suite: producer, validator integration, and every drift and doc gate.
pytest -m "not aws"

# 2. The C validator: its own unit tests plus a fixture round-trip through the real packer.
make -C validators/oca check

# 3. The variant gates still compile three ways.
for t in both classic-only pqc-only; do make -C validators/oca "$t"; done
```

AWS KMS tests are **deselected**, not skipped: they need live credentials, and `-m "not aws"`
makes their absence an explicit exclusion rather than a handful of skips that read like a
partial failure. Expect zero skips from a healthy run. Run them with `pytest -m aws` before
any release that exercises KMS signing; refresh credentials with the `aws-sso` console script.

`pytest --cov=tt_boot_manifest --cov-report=html` produces a coverage report.

### Judging the result

- **`make check` prints two `N/N passed` summaries** — the C unit-test driver, then the
  fixture sweep. Fewer than two means something declined to build and succeeded anyway; CI
  fails the run for exactly this, and so should you.
- **`make check` exits 0 down several "nothing to build" paths** left over from the skeleton
  phase: an empty `lib/`, a missing `test/unit_test.c`, zero fixtures. Each prints a notice
  and succeeds. `skipping archive`, `skipping link` and `no fixtures yet` in the output are
  failures wearing a green exit code.
- **A skip is a signal, not a pass.** The validator integration tests skip without `make` or
  `pkg-config`; the doxygen gate skips without doxygen or against 1.9.8. A broken toolchain
  therefore reads as a green run with a quietly smaller suite. Confirm the gates actually ran.
- **Judge a suite by diffing against your last known-good run**, not against an absolute pass
  count — counts drift as tests are added.

## Debugging failures

1. **Mass failures are environmental.** If tests your change never touched are failing,
   suspect the toolchain and the state of your tree before the code.
2. **A stale-object failure looks like a logic bug.** After changing `EXTRA_CFLAGS`, confirm
   the flag stamp at `validators/oca/build/lib/.cflags` holds what you expect. When in doubt,
   `make -C validators/oca clean`.
3. **Read the gate's own message.** The drift, completeness, doc-comment and retval checkers
   all report the exact symbol or line at fault, and `sync_layout.py` emits a fixup suggestion.
   Fix what it names rather than re-deriving the problem.
4. **Fix findings; do not silence them.** Adding a symbol to a `NOT_REQUIRED_*` allowlist is
   legitimate only when the field genuinely does not concern the validator, and it takes a
   one-line rationale. Widening an allowlist to make a gate quiet discards the signal the gate
   exists to produce.
5. **Reproduce the fixture by hand.** Every entry in `test/fixtures/configs/` is a YAML config
   plus a `.flags` file; packing one and running `oca-validate` on it directly, without
   `--quiet`, gives a far better error than the sweep's one-line summary.

## Coding Guidance

These rules hold for every language in the tree. Where the file being edited already has a
convention — a comment style, a case for constants — follow it rather than one carried in from
elsewhere.

### Structure

- **Helper functions are defined at module or class scope, never nested inside another
  function.** A helper that needs a caller's data takes it as a parameter. Nested `def`s hurt
  readability and testability. This applies to sources and tests alike.
- **Import aliases are descriptive and greppable.** No single-letter aliases (`import x as C`)
  and no needlessly underscore-prefixed ones (`as _entry`). A reader should be able to grep the
  alias and find the module.
- **Share one path between positive and negative verification tests.** Wrap a signature or
  hash check in a small bool-returning try/except helper, then assert `True` for the valid
  case and `False` for the tampered one. Two divergent code paths for the same check drift,
  and the negative one is the half that silently stops testing anything.

### Comments

Write a comment only to tell the reader something the code cannot: a constraint, an ordering
that matters, a hardware behavior a maintainer would otherwise have to rediscover. State it
in the present tense, as something true of the code, not as an account of what changed.

Three kinds of comment are not worth their space.

- **Narration.** Restating the line below it costs reading time and returns nothing.
- **Breadcrumbs.** Why a change was made, what it replaced, or which review asked for it
  belongs in the commit message, which stays accurate; a comment recording it is wrong after
  the next edit.
- **Justification.** Arguing that a change is correct addresses a reviewer who is gone once the
  pull request merges.

Where a test can carry the constraint instead, prefer the test: it fails when the constraint is
broken, and a comment does not.

The C library is the exception to comment brevity in one direction only: every public entity
carries a full Doxygen block, and the gates above will tell you when one is missing or wrong.

### Names

A name is held to the same rule as a comment. An identifier that describes what changed — a
field named for the size a region used to have, a constant named after a mode that was
replaced — dates as quickly as a breadcrumb, and it forces a comment to explain a concept the
code no longer has. Name what exists.

## Commits and pull requests

Follow the existing history: a title-case imperative summary, optionally prefixed with a
bracketed area tag when the change is confined to one — `[validator]`, `[CI]`. This
is not Conventional Commits: no `feat`, `fix`, `chore`, or `feat(scope):`.

```
Add a ROOT-key authorization check before revocation
[validator] Secure Boot Handling Logic Improvements
[CI] Add First Pass CI Test Runner
Optimize Payload Hash Checking
```

**Explain why in the body, not just what changed.** The best commits in this history spend
several paragraphs on the reasoning — what the old behavior permitted, what the new check
establishes, why the ordering is what it is — and that is the standard to meet, especially for
anything touching validation order or the binary contract.

Keep pull requests focused; unrelated changes belong in separate ones. Branch names follow
`<user>/<topic>`. Commit or push only when the user asks.

## Things that are easy to get wrong

| Symptom | Cause |
|---|---|
| `pytest` collection fails on a botocore import | Installed with `[dev]` only. The `aws` extra is needed even to run `-m "not aws"` |
| A green run with far fewer tests than expected | A missing toolchain turned gates into skips. Confirm `make`, `pkg-config` and a non-1.9.8 doxygen are present |
| `make check` succeeds but validated nothing | A "nothing to build" path. Look for `skipping archive`, `skipping link`, `no fixtures yet`, and for two `N/N passed` summaries |
| A gate change has no effect on the built binary | Objects were reused across an `EXTRA_CFLAGS` change. Check `build/lib/.cflags`, or clean |
| `make check` cannot import the packer | The Makefile's interpreter search found a Python without the editable install. Pass `PYTHON=<path>` explicitly |
| A new manifest field passes Python tests but the validator ignores it | The completeness gate was satisfied with an allowlist entry instead of a decoder, or the check was composed into `oca_validate()` where the staged flow skips it |
| `oca-combined` treated as a third manifest variant | It is a packaging mode that places already-built bundles; only `oca-classic` and `oca-pqc` are formats |

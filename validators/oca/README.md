<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc. -->
# OCA Validator (C library + host CLI)

A small, freestanding C library that parses an OCA boot manifest and decides
PASS or FAIL against caller-supplied hardware-identity and cryptographic
callbacks. The same library and binary handle every OCA format variant —
the magic bytes at offset 0 select the parser path. Both the Classic (`OCAC`)
and PQC (`OCAP`) framings are parsed today; PQC *signature verification* is
the one piece still outstanding (see "Not supported" below). Future variants
land here without a fork in the build system, the CLI surface, or the symbol
set.

A companion host CLI (`oca-validate`) wires the library against OpenSSL and
command-line-driven hardware values, so the same library code that runs on
silicon can be exercised end-to-end on a developer laptop.

## Layout

```
validators/oca/
├── Makefile           # build orchestration (format-agnostic)
├── INTEGRATION.md     # how to build a consumer on lib/ (cited from the header)
├── lib/               # the freestanding library (vendor this directory
│                      #   into a target firmware project)
│   ├── oca_validator.h     # SOLE public header (format-agnostic API)
│   ├── oca_validator.c     # entry point — dispatches on magic
│   ├── oca_layout.h        # field offsets (mirrors the packer constants)
│   ├── ...                 # per-format decoders
│   └── scripts/
│       └── sync_layout.py  # drift check against src/oca/constants.py
└── test/              # host harness (NEVER ship to silicon)
    ├── main.c           # the CLI driver
    ├── unit_test.c      # in-tree C unit tests
    └── fixtures/
        ├── configs/     # YAML configs that drive `make check`
        └── *.bin        # generated binaries (gitignored)
```

## Build

```
make             # builds test/oca-validate (default target)
make lib         # builds the host static archive only
make unit_test   # builds and runs the in-tree C unit tests
make check       # unit tests + packer-fixture round-trip sweep
make clean
```

The library compiles `-std=c99 -Wall -Wextra -Werror -pedantic
-ffreestanding -nostdlib`. The host CLI links OpenSSL 3 (`-lcrypto`).

### Compile-time overrides

`EXTRA_CFLAGS` is the single hook for the feature gates (`OCA_TOC_MAX_IMAGES`,
`OCA_SUPPORT_PQC=0`, …):

```sh
make EXTRA_CFLAGS="-DOCA_TOC_MAX_IMAGES=32" test
```

Changing `EXTRA_CFLAGS` does force a rebuild. `make` decides what to recompile from file
timestamps and never from the command line it last used, so the build records the
flags in a stamp file (`build/*/.cflags`) that every object depends on. Without
that, changing a `-D` and rebuilding into the same directory silently reused
objects compiled with the previous value — a binary that did not match the flags
you asked for, which has produced wrong test verdicts. The stamp is rewritten only
when the flags actually differ, so an unchanged rebuild stays incremental. This is
independent of your make version: **no** make tracks the command line it last used,
so the stamp is required regardless.

The `classic-only` / `pqc-only` targets use separate `BUILD` directories, so they
never contend with the default build. Do the same for ad-hoc experiments if you
want to keep both around:

```sh
make BUILD=build/cap32 EXTRA_CFLAGS="-DOCA_TOC_MAX_IMAGES=32" all
```

#### Available gates

| Symbol | Default | Effect |
|---|---|---|
| `OCA_SUPPORT_CLASSIC` | `1` | Compile in the `OCAC` variant. |
| `OCA_SUPPORT_PQC` | `1` | Compile in the `OCAP` variant. |
| `OCA_TOC_MAX_IMAGES` | `256` | Cap on payload TOC entries this build will process. |
| `OCA_RECHECK_SECURITY_VERSION` | `1` | Re-evaluate anti-rollback after the signature verifies. |

`OCA_RECHECK_SECURITY_VERSION` is worth understanding before turning it off. The
anti-rollback comparison runs *before* signature verification, so a replayed
manifest is rejected without paying for a public-key operation. That early
evaluation is sound in the rejection direction: the compared value is inside the
signed region, so a manifest altered to change the outcome fails verification
anyway.

The second evaluation, which this gate controls, is therefore defence in depth
rather than correctness — it catches a fault that skipped or glitched past the
first. Setting it to `0` saves one device-state read and one 16-byte compare on
the accept path, against a signature verification that dominates both. Disable it
only on a target that genuinely cannot afford that, and knowing what is given up.

**If you script builds, use GNU Make 4.x.** older version of make (such as 3.81 that 
macOS ships) compares timestamps at whole-second granularity. A script that rewrites 
a source file and rebuilds within the same second gets `Nothing to be done` and a stale
binary. 

Interactive editing never hits this, since seconds always pass between saving and
building. Scripted A/B harnesses that swap files in and out do. `brew install make`
provides 4.x as `gmake`, which resolves it:

```sh
gmake -C validators/oca check
```

Verified as a drop-in — 4.4.1 produces the same results as 3.81 for every target,
with no warnings. On the bundled 3.81, `make clean` between variants is the
workaround.

Expected `make check` output (tail) — every unit test + every fixture
round-trip passes:

```
245/245 passed
PASS: all_constraints
PASS: basic
PASS: control_plane
PASS: encrypted_aes
PASS: encrypted_aes_pqc
PASS: multi_image
PASS: pqc_basic
PASS: pqc_secure_rsa
PASS: secure_ecdsa
PASS: secure_rsa
PASS: secure_rsa_der
PASS: secure_rsa_e3
PASS: secure_rsa_e3_der
13/13 passed
check: complete
```

(Counts grow as tests and fixtures are added; the shape is what matters — every
unit test and every fixture round-trip passes.)

### Prerequisites

- A host C toolchain (gcc 12+ or clang 16+) with `-std=c99` support.
- GNU Make. 3.81 (what macOS bundles) works for ordinary use; **4.x is preferred
  if you script builds** — see "Compile-time overrides" for why.
- OpenSSL 3 development headers, discovered via `pkg-config` (macOS:
  `brew install openssl@3`; Debian/Ubuntu: `apt install libssl-dev`).
- For `make check` only: a Python environment with the project's
  `tt_boot_manifest` packer installed. The Makefile invokes
  `python -m tt_boot_manifest.pack_images` to (re-)generate fixture
  binaries; without the package on the import path the target fails
  early with an actionable error.

If your project venv is not on `PATH`, either activate it before
running `make check`:

```sh
source /path/to/your/venv/bin/activate
make check
```

or point `make` at the venv's interpreter directly:

```sh
make PYTHON=/path/to/your/venv/bin/python check
```

The Makefile also auto-discovers a venv at `<repo>/.venv` or
`<repo>/venv` if one exists; nothing to configure when that's the case.

## Run

```
./build/test/oca-validate --manifest <path-to-bundle>.bin
```

`--help` prints the full flag set. Output is a single line:

- `PASS: <manifest_identifier> v<M.m.p>` on stdout, exit 0.
- `FAIL: <CATEGORY>: <reason>` on stderr, exit 1 (exit 2 for usage errors).

## Supported algorithm portfolio

The
[OCA boot manifest specification](https://www.openchipletatlas.org/specifications/oca/latest)
asks every consumer implementor to document the "security portfolio" — the
algorithms and manifest capabilities it supports. This library accepts the
following and rejects everything else it is asked to act upon on the current
boot path.

| Manifest field | Supported value(s) | Notes |
|----------------|--------------------|-------|
| manifest format (magic) | `OCAC` (classic), `OCAP` (PQC) | one library parses both; magic selects the path |
| `manifest_hash_type` | SHA2-256 (`0x01`) | the only digest this build recomputes |
| `signature_type_classic` | RSA-3072-PKCS#1v1.5-SHA256 (`0x01`), ECDSA-P256-SHA256 (`0x05`) | the primitive is passed to the host `verify_signature` callback; the callback owns the math |
| `signature_encoding_classic` / `public_key_encoding_classic` | ASN.1 DER (`0x01`) | |
| `encryption_type` | AES-128-CBC (`0x01`) or AES-256-CBC (`0x02`) + PKCS#7 | payload decryption is delegated to the host `decrypt_payload` callback; the key length follows the type |
| `encryption_key_derivation_function` | NIST SP 800-108r1 CTR-HMAC-SHA256 (`0x0001`) | key material is provisioned host-side; the KDF consumes a 192-byte structured input block (see below) |
| `input_key_source` | pre-shared secret (b001) | |
| payload `image_count` | 1 .. `OCA_TOC_MAX_IMAGES` (default **256**) | a consumer resource limit, not a format limit — see below |

**Payload TOC size limit.** The format sets no upper bound on `image_count`, so
the only structural constraint is that the TOC fit inside the payload — a bound
that grows with the input, while the TOC's pairwise overlap check is
O(`image_count`²). An 8 MiB payload admits 30393 entries and 4.6×10⁸ comparisons,
and that work is reachable *before* any signature check when secure boot is
disabled, since `manifest_hash` and `payload_hash` are unkeyed SHA-256 that
anyone able to write flash can recompute.

This build therefore caps `image_count` at `OCA_TOC_MAX_IMAGES` (256 by default,
far above any real boot payload) and reports
`OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES` — deliberately distinct from
`OCA_FAIL_PAYLOAD_TOC` so a field failure distinguishes "this consumer refuses a
manifest this large" from "this TOC is malformed". Tighten it for a smaller
budget:

```
make EXTRA_CFLAGS="-DOCA_TOC_MAX_IMAGES=32"
```

Note this is a documented *deviation*: a manifest above the cap may be entirely
spec-legal. The spec states the principle that a Consumer may refuse what its own
portfolio cannot support, and a resource ceiling is the same kind of declaration —
which is why it is recorded here rather than left implicit in a buffer size.

Cryptography itself is never performed inside the library — SHA-256, signature
verification, and payload decryption are all host-supplied callbacks (see
`oca_validator.h`). This table describes which manifest-declared algorithm
*values* the library is prepared to route to those callbacks.

**Payload-key derivation (interoperability contract).** When
`encryption_key_derivation_function` is `0x0001`, the AES key is derived with
NIST SP 800-108r1 counter mode (HMAC-SHA-256) over a fixed **192-byte input
block**, not over the manifest's KDF-input field alone. The block is
`header(32) ‖ label(32) ‖ context(64) ‖ entropy(64)`, where the header carries
fixed key-purpose/domain metadata (with the derived-key length in its `out_bits`
field), the label is the ASCII string `KM_CLASS_BL` (null-padded), the context
is the manifest's `encryption_kdf_input` field, and the entropy region is zero.
The PRF stream is `HMAC-SHA-256(key, be16(i) ‖ block ‖ be16(L))` truncated to
`L/8` bytes, with the 16-bit counter `i` starting at 1 and `L` the derived-key
length in bits (128 for AES-128-CBC, 256 for AES-256-CBC). A producer and
consumer that do not build these bytes identically cannot exchange an encrypted
payload. The pre-shared secret is the HMAC key; the derivation binds no device
state, so it is reproducible in every lifecycle state.

**Not supported (rejected or not yet verified).** These are documented so an
integrator knows the current boundary; several are tracked as follow-on work:

- **A PQC signature backend** — the library side of PQC verification is in
  place. The manifest `secure_boot_classic` / `secure_boot_pqc` class control 
  bits are enforced. Secure boot with neither class named is rejected, as is `secure_boot_pqc` on a classic manifest. Each enforced class's ROOT key is authorized against its own anchor and its signature dispatched through `verify_signature` with the blob's `key_algorithm` naming the family.
  A hybrid signed manifest is verified as logical AND with either class failing causing a rejection. What does not exist is any in-tree PQC implementation: the reference harness verifies classical RSA/ECDSA only and fails closed on `OCA_KEY_ALGO_PQC`, and the packer cannot yet produce a PQC-signed manifest. 
  The PQC size fields get bounds validation only; per-algorithm exact sizes (ML-DSA / SLH-DSA) are pinned when a backend exists to consume them.
- **Composite CBC-HMAC and AEAD (e.g. GCM-SIV) encryption modes**, and
  **KEM-unwrapped DEK** (`input_key_source` b010) — only plain AES-128-CBC and
  AES-256-CBC with a pre-shared secret are handled.
- **PQC ROOT-key revocation** — classic ROOT-key revocation and anti-rollback
  *are* implemented (see [Secure-boot device state](INTEGRATION.md#secure-boot-device-state));
  the PQC key is authorized against the device's anchor but its
  `public_key_pqc_revoke` bitmap and the PQC half of the device revocation
  state are not yet consulted.
- **Verifier key entry and co-signer entry verification** — the appended-entry
  trust chain is not walked.
- **Boot-time enforcement of the signature posture registers** — the
  `signature_cohort_enforce` and `signature_class_revoke` fields are validated
  (including the group-code interlock) and OR-ed into device state by the
  post-verify commit, but the *accumulated* state is not yet consulted at boot.
  This build will not reject a signature whose algorithm class the device has
  revoked, nor require a cohort the device demands beyond what the manifest's
  own class bits already name — the per-class dispatch those registers need
  exists now, but the accumulated device state is not yet read back into it.
- **The encrypted-payload padding bound** — for an encrypted payload this build
  requires the manifest's `payload_length` to equal `payload_hashed_length` and
  to cover at least a one-entry TOC, but does not yet check it against the TOC's
  own `payload_length` within one cipher block. The cleartext equality check
  *is* implemented.

## Integrating into a target firmware project

See **[INTEGRATION.md](INTEGRATION.md)** — vendoring, the callback table an
implementor must provide, choosing an entry point, the staged flow for booting
from external storage, reaching the plaintext payload (including in-place
decryption), walking the TOC, and the secure-boot device-state contract.

## Producer/consumer lock-step (enforced automatically)

The Python packer (`src/oca/`) and this C validator have to agree
byte-for-byte on the manifest layout. We enforce that with tests, not
PR-review checklists — drift fails CI loudly before any manual review.

Two automated gates:

### 1. Drift gate

`tests/test_oca_c_validator_layout_sync.py` runs `scripts/sync_layout.py`
on every `pytest` invocation. The script compares every
`OCA_CLASSIC_OFF_*` / `OCA_CLASSIC_LEN_*` / mask in `lib/oca_layout.h`
against its `tt_boot_manifest.oca.constants` counterpart. Any mismatch
fails the test with a unified diff and a `sed` fixup suggestion.

### 2. Completeness gate

The same script also enumerates every `OFF_*` / `LEN_*` constant in
`tt_boot_manifest.oca.constants` and verifies each one is either
mapped to a C-side mirror in `MAPPING` or explicitly listed in the
`NOT_REQUIRED_PREFIXES` / `NOT_REQUIRED_EXACT` allowlist with a
one-line rationale. The result: you cannot add a new manifest field on
the Python side and silently leave the C validator behind.

### What this looks like when you add a field

1. Add the new `OFF_FOO` / `LEN_FOO` to `src/oca/constants.py`.
2. Run `pytest tests/test_oca_c_validator_layout_sync.py`. It fails:
   `OFF_FOO ... not mapped to the C side`.
3. Either:
   - Validator-relevant: add `OCA_CLASSIC_OFF_FOO` to
     `lib/oca_layout.h` and an entry to `MAPPING` in `sync_layout.py`.
     If the new field is constraint-bearing, write the per-field
     decoder under `lib/` (new `oca_check_foo()`, composed into
     `oca_validate_manifest()` for a manifest-level check or
     `oca_check_payload()` for a payload one — **not** into
     `oca_validate()`, which would leave the staged flow skipping it),
     add a fixture under `test/fixtures/configs/`, and add a
     corresponding integration test. Compose cheap checks before the
     signature: a manifest that cannot boot should cost as little as
     possible to reject. If the new check applies only under secure
     boot, take an `oca_validation_context_t *` and open with
     `oca_secure_boot_confirm()` rather than deriving the answer
     yourself: see `lib/secure_boot.h`.
   - Not validator-relevant: add the symbol to `NOT_REQUIRED_PREFIXES`
     in `sync_layout.py` with a one-line "why this is OK" comment.
4. `make -C validators/oca check` and `pytest -m "not aws"` both
   pass → land the change.

The pattern is: when you change the Python side without thinking about
the C side, the test tells you exactly what's missing and what to do
about it.

<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc. -->
# OCA Validator (C library + host CLI)

A small, freestanding C library that parses an OCA boot manifest and decides
PASS or FAIL against caller-supplied hardware-identity and cryptographic
callbacks. The same library and binary handle every OCA format variant —
the magic bytes at offset 0 select the parser path. Both the Classic (`OCAC`)
and PQC (`OCAP`) variants are parsed and verified, including PQC-only and
hybrid signatures; the cryptography itself stays in the integrator's callbacks.
Future variants land here without a fork in the build system, the CLI surface,
or the symbol set.

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
│   ├── oca_config.toml     # the default build configuration
│   ├── oca_config_check.h  # refuses a missing, stale or hand-edited oca_config.h
│   ├── ...                 # per-format decoders
│   └── scripts/
│       ├── gen_config.py   # generates oca_config.h from a build configuration
│       └── sync_layout.py  # drift check against src/oca/constants.py
└── test/              # host harness (NEVER ship to silicon)
    ├── main.c           # the CLI driver
    ├── unit_test.c      # in-tree C unit tests
    ├── build_configs/   # build configurations for the variant-gated targets
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
-ffreestanding -nostdlib`. The host CLI links OpenSSL 3.5 or later (`-lcrypto`).

### Build configuration

Every compile-time setting of the library lives in one TOML file. The build
generates `build/gen/oca_config.h` from it before compiling anything, and the
library does not compile without that header. `lib/oca_config.toml` is the
default; name another with `CONFIG`:

```sh
make CONFIG=path/to/board.toml test
```

A configuration **replaces** the default rather than adjusting it. Every setting
must be stated, an unknown or misspelled key is an error, and the generator
reports every problem in one pass. When a library upgrade adds a setting, your
build stops until you choose its value, instead of inheriting one nobody
reviewed. The settings' former `-D` forms (`-DOCA_TOC_MAX_IMAGES=32` and the
rest) are refused at compile time, naming the key that replaced each.
`EXTRA_CFLAGS` remains for compiler flags only: sanitizers, warnings,
optimization.

The generator, `lib/scripts/gen_config.py`, needs Python 3.11 or later and
nothing beyond its standard library. The Makefile runs it with `PYTHON` when you
set one, `python3` otherwise, and `CONFIG_PYTHON` overrides both. It rewrites
the header only when the content changes, so an unchanged build stays
incremental while editing the file, or switching `CONFIG`, rebuilds what
depends on it. `INTEGRATION.md`, "Configuring the build", covers generating the
header from another build system.

Changing `EXTRA_CFLAGS` forces a rebuild too. `make` decides what to recompile
from file timestamps and never from the command line it last used, so the build
records the flags in a stamp file (`build/*/.cflags`) that every object depends
on. Without that, changing a flag and rebuilding into the same directory silently
reused objects compiled with the previous value — a binary that did not match the
flags you asked for, which has produced wrong test verdicts. The stamp is
rewritten only when the flags actually differ, so an unchanged rebuild stays
incremental. This is independent of your make version: **no** make tracks the
command line it last used, so the stamp is required regardless.

The `classic-only` / `pqc-only` targets build from `test/build_configs/` into
separate `BUILD` directories, so they never contend with the default build. Do
the same for ad-hoc experiments if you want to keep both around:

```sh
make BUILD=build/cap32 CONFIG=path/to/cap32.toml all
```

#### Settings

| Key | Default | Effect |
|---|---|---|
| `[variants] classic` | `true` | Accept the `OCAC` variant. |
| `[variants] pqc` | `true` | Accept the `OCAP` variant. |
| `[limits] toc_max_images` | `256` | Cap on payload TOC entries this build will process (exposed to code as `OCA_TOC_MAX_IMAGES`). |
| `[hardening] recheck_security_version` | `true` | Re-evaluate anti-rollback after the signature verifies (`OCA_RECHECK_SECURITY_VERSION`). |

| `[signature_classic] rsa_3072_pkcs1v15_sha256` | `true` | Verify RSA-3072, RSASSA-PKCS1-v1_5, SHA-256. |
| `[signature_classic] ecdsa_p256_sha256` | `true` | Verify ECDSA P-256, SHA-256. |
| `[signature_pqc] ml_dsa_87` | `true` | Verify FIPS 204 ML-DSA-87. Needs `[variants] pqc`. |
| `[der] rsa_public_key` | `true` | Accept DER (PKCS#1) RSA public keys. Needs an RSA algorithm. |
| `[der] ecdsa_signature` | `true` | Accept DER ECDSA signatures. Needs an ECDSA algorithm. |
| `[encryption_cipher] aes_128_cbc` | `true` | Decrypt AES-128-CBC payloads. |
| `[encryption_cipher] aes_256_cbc` | `true` | Decrypt AES-256-CBC payloads. |
| `[encryption_kdf] sp800_108_hmac_sha256` | `true` | Derive the payload key with SP 800-108r1 counter mode, HMAC-SHA-256. |
| `[encryption_key_source] preshared` | `true` | Take the input key from a provisioned secret. |

A cipher, a KDF and a key source are enabled together or not at all. A build
that enables none of them refuses every encrypted payload.

At least one variant must be on. A variant turned off is refused with
`OCA_FAIL_UNSUPPORTED_VARIANT` instead of validated.

The algorithm sections are the build's portfolio, and they work differently
from the settings above: an algorithm or encoding the file does not name is
off, so the file lists what the build accepts and nothing is accepted by
default. At least one signature algorithm must be on. Every algorithm the
format defines may be named — `lib/oca_config.toml` lists them — but only those
with a row in `lib/algorithms.c` may be turned on; turning on any other stops
the generator, naming it as not implemented. A manifest that names an
algorithm or DER encoding the build leaves off is refused with
`OCA_FAIL_ALGORITHM_NOT_ENABLED`, before any signature is checked.

`recheck_security_version` is worth understanding before turning it off. The
anti-rollback comparison runs *before* signature verification, so a replayed
manifest is rejected without paying for a public-key operation. That early
evaluation is sound in the rejection direction: the compared value is inside the
signed region, so a manifest altered to change the outcome fails verification
anyway.

The second evaluation, which this setting controls, is therefore defence in depth
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
315/315 passed
PASS: all_constraints
PASS: basic
PASS: control_plane
PASS: encrypted_aes
PASS: encrypted_aes_pqc
PASS: encrypted_aes_pqc_mldsa
PASS: multi_image
PASS: pqc_basic
PASS: pqc_hybrid_ecdsa
PASS: pqc_hybrid_rsa
PASS: pqc_secure_mldsa
PASS: pqc_secure_rsa
PASS: secure_ecdsa
PASS: secure_rsa
PASS: secure_rsa_der
PASS: secure_rsa_e3
PASS: secure_rsa_e3_der
17/17 passed
check: complete
```

(Counts grow as tests and fixtures are added; the shape is what matters — every
unit test and every fixture round-trip passes.)

### Prerequisites

- A host C toolchain (gcc 12+ or clang 16+) with `-std=c99` support.
- GNU Make. 3.81 (what macOS bundles) works for ordinary use; **4.x is preferred
  if you script builds** — see "Compile-time overrides" for why.
- OpenSSL 3.5 or later development headers, discovered via `pkg-config` (macOS:
  `brew install openssl@3`; Debian 13+ or Ubuntu 26.04+: `apt install libssl-dev`).
  The CLI verifies ML-DSA-87, which OpenSSL provides from 3.5. When `pkg-config`
  finds OpenSSL, `make` checks its version before linking the CLI
  (`OPENSSL_MIN_VERSION`); with `OPENSSL_CFLAGS` supplied by hand, the same
  minimum is enforced at compile time. The library and the unit tests do not use
  OpenSSL.
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
algorithms and manifest capabilities it supports. This library can accept the
following, and the default build configuration enables all of it. A build's
configuration chooses which of these it accepts ([Settings](#settings)); a
manifest naming an algorithm the build does not enable is refused with
`OCA_FAIL_ALGORITHM_NOT_ENABLED`, and one naming a value the format reserves
with `OCA_FAIL_ALGORITHM_RESERVED`. Everything else the library is asked to act
upon on the current boot path is rejected too.

| Manifest field | Supported value(s) | Notes |
|----------------|--------------------|-------|
| manifest format (magic) | `OCAC` (classic), `OCAP` (PQC) | one library parses both; magic selects the path |
| `manifest_hash_type` | SHA2-256 (`0x01`) | the only digest the library recomputes; any other is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED` before anything is hashed |
| `payload_hash_type` | SHA2-256 (`0x01`) | covers `payload_hash`, the chain and every TOC entry hash; any other is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED` when a payload is declared |
| `signature_type_classic` | RSA-3072-PKCS#1v1.5-SHA256 (`0x01`), ECDSA-P256-SHA256 (`0x05`) | the primitive is passed to the host `verify_signature` callback; the callback owns the math. Under secure boot, any other algorithm the format defines is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED`, a reserved value with `OCA_FAIL_ALGORITHM_RESERVED` |
| `signature_encoding_classic` / `public_key_encoding_classic` | raw (`0x02`); ASN.1 DER (`0x01`) for RSA public keys and ECDSA signatures | each DER encoding can be turned off in `[der]`, after which it is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED`; DER for any other value is `OCA_FAIL_CRYPTO_FIELD_SIZE`. Under secure boot, every key and signature field of an enforced class must be zero past its declared size, or the manifest is refused with `OCA_FAIL_CRYPTO_FIELD_SIZE` |
| `secure_boot_control` signature classes | classical, PQC, or both (hybrid) | under secure boot at least one class must be set, and the PQC class only on an `OCAP` manifest (else `OCA_FAIL_SIGNATURE_CLASS_CONTROL`); each enforced class's key is authorized against its own anchor family, and a hybrid manifest needs both signatures to verify |
| `signature_type_pqc` | ML-DSA-87 (`0x33`) | pure FIPS 204 over the signed region, empty context; the host `verify_signature` callback owns the math. ML-DSA-44 / -65 and SLH-DSA are refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED`, a reserved value (including `0x41` / `0x42`, held for FN-DSA) with `OCA_FAIL_ALGORITHM_RESERVED` |
| `signature_encoding_pqc` / `public_key_encoding_pqc` | raw (`0x02`) only, with exact sizes: 4627-byte signature, 2592-byte key | any other encoding or size is refused with `OCA_FAIL_CRYPTO_FIELD_SIZE` |
| device signature posture (`signature_class_revoke`, `signature_cohort_enforce` as committed) | per-algorithm class bits and the `0xCA` / `0xAC` group codes; the ROOT key's cohort nibble | applied at every secure boot by `oca_check_signature_posture()`: an enforced class whose algorithm the device has disabled is refused with `OCA_FAIL_SIGNATURE_ALGORITHM_REVOKED`, and a manifest that does not enforce a cohort the device demands of the ROOT key with `OCA_FAIL_SIGNATURE_COHORT_REQUIRED` |
| `encryption_type` | AES-128-CBC (`0x01`) or AES-256-CBC (`0x02`) + PKCS#7 | payload decryption is delegated to the host `decrypt_payload` callback; the key length follows the type. Any other cipher is refused before the ciphertext is hashed: `OCA_FAIL_ALGORITHM_NOT_ENABLED` for one the format defines, `OCA_FAIL_ALGORITHM_RESERVED` otherwise |
| `encryption_key_derivation_function` | NIST SP 800-108r1 CTR-HMAC-SHA256 (`0x0001`) | key material is provisioned host-side; the KDF consumes a 192-byte structured input block (see below). Any other value on an encrypted payload is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED`, or `OCA_FAIL_ALGORITHM_RESERVED` for one the format reserves |
| `input_key_source` | pre-shared secret (b001) | the KEM-unwrapped DEK (b010) is refused with `OCA_FAIL_ALGORITHM_NOT_ENABLED`; every other pattern, including none and two sources at once, with `OCA_FAIL_ALGORITHM_RESERVED` |
| payload `image_count` | 1 .. `toc_max_images` (default **256**) | a consumer resource limit, not a format limit — see below |

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
budget with `toc_max_images` in the `[limits]` section of your build
configuration.

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
integrator knows the current boundary:

- **Signature algorithms other than RSA-3072-PKCS#1v1.5, ECDSA-P256 and
  ML-DSA-87** — the library has no rules for the format's other RSA, ECDSA,
  EdDSA, ML-DSA and SLH-DSA algorithms, so no build configuration can turn one
  on (the generator stops the build). Manifests naming them are refused with
  `OCA_FAIL_ALGORITHM_NOT_ENABLED`. Adding one means adding its row to
  `lib/algorithms.c` and marking it implemented in `lib/scripts/gen_config.py`.
- **Composite CBC-HMAC and AEAD (e.g. GCM-SIV) encryption modes, SM4, KDFs
  other than SP 800-108r1 with HMAC-SHA-256, and the KEM-unwrapped DEK**
  (`input_key_source` b010) — only plain AES-128-CBC and AES-256-CBC, derived
  from a pre-shared secret, can be enabled. The others are listed in the build
  configuration and refused there as not implemented.
- **Verifier key entry and co-signer entry verification** — the appended-entry
  trust chain is not walked.
- **Cohort enforcement for the verifier key and co-signers** — the device's
  signature posture is applied at boot to the ROOT key's signatures only. The
  verifier-key and co-signer nibbles of `signature_cohort_enforce` are
  committed to device state but not consulted, because those entries are not
  verified.

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
on every `pytest` invocation. The script compares every mapped offset,
length and mask in the layout headers — the shared `lib/oca_layout.h`
and the variant headers `lib/oca_layout_classic.h` and
`lib/oca_layout_pqc.h` — against its `tt_boot_manifest.oca.constants`
counterpart. Any mismatch fails the test with a unified diff and a `sed`
fixup suggestion.

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
   - Validator-relevant: add the mirror — `OCA_OFF_FOO` in
     `lib/oca_layout.h` for a field shared by every variant, or an
     `OCA_CLASSIC_` / `OCA_PQC_` name in that variant's header — and an
     entry to `MAPPING` in `sync_layout.py`.
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

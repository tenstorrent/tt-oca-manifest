# Tenstorrent OCA Boot Manifest

## Overview

This repository is the home of the **OCA (Open Chiplet Atlas) boot manifest**: the format
specification, the Python producer tooling, and the C consumer/validation library.

- **Specification** — the authoritative AsciiDoc format spec lives at
  [specifications/oca/boot-manifest.adoc](specifications/oca/boot-manifest.adoc); `make spec-pdf`
  renders it to PDF (see [Building the specification PDF](#building-the-specification-pdf)).
- **Producer** — a Python package (`tt_boot_manifest`) that constructs, signs, and
  optionally encrypts OCA boot manifest bundles from YAML configuration files.
- **Consumer** — a freestanding C validator library plus host CLI under
  [validators/oca/](validators/oca/) that reads bundles back the same way the silicon's
  on-chip parser will.

An OCA manifest is a fixed-layout body followed by a `PTOC`-prefixed payload
table-of-contents, with two on-disk variants: `oca-classic` (magic `OCAC`) and
`oca-pqc` (magic `OCAP`). The format provides robust anti-rollback and security
controls, layout for co-signer and assigned-key (verifier-key) entries, and a
managed path for the post-quantum transition.

Key features:
- **Manifest-based packaging**: YAML config files define the bundle; `manifest_format` picks the variant
- **Secure boot / signing**: RSA-3072 and ECDSA P-256, via local keys, AWS KMS, or HSM (future)
- **Payload encryption**: AES-256-CBC (default) or AES-128-CBC, keyed by a
  NIST SP 800-108r1 KDF over a 192-byte structured input block
- **Usage constraints**: chiplet/package/system-ID, lifecycle, version-range, and demotion gating
- **Device-state security**: ROOT-key revocation and anti-rollback security version checks, enforced by the OCA validator
- **Python package**: installable via pip for easy integration

## Prerequisites

For the Python packer:

- **Python 3.9+**
- **pip** (Python package installer)

Additionally, for building and running the OCA C validator (and the test suite's
validator integration tests, which skip without it):

- A host **C toolchain** with `-std=c99` support (gcc 12+ or clang 16+)
- **OpenSSL 3** development headers, discovered via **pkg-config**
  (macOS: `brew install openssl@3`; Debian/Ubuntu: `apt install libssl-dev pkg-config`)
- **doxygen**, for the documentation gate test, which skips without it. Any
  current release works **except 1.9.8** — the version Ubuntu's apt currently
  packages — which falsely reports documented functions as undocumented
  ([doxygen/doxygen#11147](https://github.com/doxygen/doxygen/issues/11147),
  fixed in 1.13.0). The test detects that defect and skips with an
  explanation; CI pins 1.18.0.

And, for rendering the specification to PDF:

- **asciidoctor-pdf** — `gem install asciidoctor-pdf` (macOS:
  `brew install asciidoctor && gem install asciidoctor-pdf`; Debian/Ubuntu:
  `apt install ruby-asciidoctor-pdf`). Nothing else in the repository needs it,
  and no test depends on it.

## Installation

### Package Dependencies

The package is configured via `pyproject.toml` with the following dependencies:

**Core dependencies:**
- `cryptography>=41.0.0` - Cryptographic operations (RSA, ECDSA, AES, hashing)
- `ruamel.yaml>=0.17.0` - YAML configuration parsing (preserves comments and formatting)

**Optional dependencies:**
- `boto3>=1.40.0` - AWS KMS integration (install with `[aws]`)
- `pytest>=7.0.0` - Test framework (install with `[dev]`)
- `pytest-cov>=4.0.0` - Test coverage reporting (install with `[dev]`)

### Install as a Python Package

Install the package in your Python environment:

```bash
# Basic installation (core dependencies only)
pip install -e .

# With development dependencies (includes pytest, pytest-cov)
pip install -e ".[dev]"

# With AWS KMS support (includes boto3 for AWS signing)
pip install -e ".[aws]"

# Install everything (dev + AWS dependencies)
pip install -e ".[dev,aws]"
```

The distribution is named `tt-oca-manifest`; the import package is
`tt_boot_manifest`, so existing `python -m tt_boot_manifest.pack_images`
workflows work unchanged.

## Package Structure

The package is organized as follows:

```
tt-oca-manifest/
├── src/                          # tt_boot_manifest package
│   ├── pack_images.py            # CLI entry point; dispatches on manifest_format
│   ├── pack_images_constants.py  # Signing/encryption constants shared by the tooling
│   ├── manifest_signing.py       # Signing infrastructure (local, AWS, HSM)
│   ├── aes128cbc.py              # AES-128-CBC (encryption_type 0x01)
│   ├── aes256cbc.py              # AES-256-CBC (encryption_type 0x02, the default)
│   ├── utils.py                  # Configuration loading and validation
│   └── oca/                      # Producer for oca-classic / oca-pqc
│       ├── entry.py              #   OCA assembly entry point (pack_oca_bundle)
│       ├── constants.py          #   OCA offsets/sizes/enums — source of truth for the C mirror
│       ├── validators.py         #   Config validation + deferred-feature rejection
│       ├── combined.py           #   oca-combined multi-manifest image assembly
│       └── ...                   #   manifest/payload/encryption/usage-constraints builders
├── validators/
│   └── oca/                      # Consumer: freestanding C validator library + host CLI (oca-validate)
├── specifications/
│   ├── theme.yml                 # Asciidoctor PDF theme used by `make spec-pdf`
│   └── oca/                      # The OCA boot manifest format specification (AsciiDoc + figures)
├── tools/
│   └── aws_sso.py                # AWS SSO credential refresh (the `aws-sso` console script)
├── tests/                        # Test suite (pytest) — producer, signing, and C-validator integration
│   ├── signing_keys/             # Test signing keys (development only)
│   ├── test_manifest_signing.py  # Signing and verification tests
│   ├── test_oca_*.py             # Producer, signing, encryption, PQC, combined, validator tests
│   └── conftest.py               # Pytest configuration
├── configs/                      # Example YAML configs (oca_*.yaml)
├── examples/                     # Usage examples
├── Makefile                      # Renders the specification to build/oca-boot-manifest.pdf
└── pyproject.toml                # Package metadata and dependencies
```

### Import Structure

**Source files** (`src/`) use **relative imports** to function as a proper Python package:
```python
# Inside src/ files
from .utils import load_config
from .pack_images_constants import *
```

**Test files** (`tests/`) import from the **installed package**:
```python
# Inside tests/ files
from tt_boot_manifest.utils import load_config
from tt_boot_manifest.pack_images import generate_images
```

This structure ensures the package works correctly when installed via pip while maintaining a clean test environment.

## Quick Start

### Using the Package Programmatically

```python
from tt_boot_manifest.pack_images import pack_images

# Generate a signed OCA bundle from a YAML configuration
success = pack_images(
    config_path="configs/oca_classic_example.yaml",
    output_path="out/oca_classic.bin",
    verbose=True
)

if success:
    print("✓ Manifest generation completed!")
```

The config's **required** `manifest_format` field selects the packer:
`oca-classic` or `oca-pqc` builds a single bundle; `oca-combined` assembles
already-configured bundles into one deployable image.

### Command-Line Usage

```bash
python -m tt_boot_manifest.pack_images \
    --config configs/oca_classic_example.yaml \
    --out out/oca_classic.bin \
    -v
```

See [examples/oca_classic_basic/](examples/oca_classic_basic/) for a complete
worked example, including independent verification of the output.

## OCA Manifest Generation

Every OCA manifest is a fixed-layout body followed by a `PTOC`-prefixed payload
TOC (276-byte entries), signed through the `local` / `aws` signing authorities.

### OCA manifest variants

OCA defines two manifest variants that flow through one assembly path and are
read back by one validator. Field names are shared, not variant-prefixed: a
field present in both variants has the same name and (where the layout allows)
the same offset.

| `manifest_format` | Magic | Body size | Description |
|-------------------|-------|-----------|-------------|
| `oca-classic` | `OCAC` | 4096 bytes | Classical-crypto manifest. |
| `oca-pqc` | `OCAP` | 36864 bytes | Post-Quantum manifest — a **superset** of Classic: every shared field keeps its Classic offset, with the PQC-only fields inserted ahead of the unsigned tail. |

A PQC manifest may be signed today with a classic RSA-3072 / ECC P-256 key —
the same signing path covers both variants, computing the signature over each
variant's signed region. PQC-native signing (ML-DSA / FN-DSA / SLH-DSA) and
KEM (ML-KEM) are deferred and rejected fast (see the table below).

See [examples/oca_classic_basic/](examples/oca_classic_basic/) for a runnable
Classic demo, and [configs/oca_pqc_example.yaml](configs/oca_pqc_example.yaml)
for a runnable non-secure PQC example.

### Supported / deferred OCA features (beta release)

| Area | Supported | Deferred to a future feature pass |
|------|-----------|-----------------------------------|
| Format selector | `oca-classic`, `oca-pqc`, `oca-combined` | — |
| Signature algorithm | RSA-3072 PKCS#1 v1.5 + SHA-256 (`0x01`), ECC P-256 + SHA-256 (`0x05`) — for both variants | RSA-PSS, RSA-4096, ECC P-384, Ed25519; PQC-native signing (ML-DSA, FN-DSA, SLH-DSA) and KEM (ML-KEM) |
| Hash algorithm | SHA-256 (`0x01`) | All others (`manifest_hash_type` / `payload_hash_type` ≠ `0x01`) |
| Signing authority | `local`, `aws` | `hsm` |
| Payload encryption | AES-256-CBC (`0x02`, the default) and AES-128-CBC (`0x01`), key derived from a pre-shared secret via SP 800-108r1 CTR-HMAC-SHA-256 over the 192-byte input block (`local` authority) | KEM-wrapped keys, any other cipher or KDF identifier, `aws` / `hsm` encryption authority |
| Multi-image payload | Yes (`PTOC` TOC of 276-byte entries; images 8-byte aligned) | — |
| ROOT-key revocation & anti-rollback | Classic `public_key_classic_revoke`, `manifest_security_version` (128 posture flags), and `manifest_security_control` update controls — the validator enforces revoke-before-key-use, bit-superset anti-rollback, and a post-verify device-state commit | PQC ROOT-key revocation (lands with PQC signature verification) |
| Signature posture registers | `signature_cohort_enforce` and `signature_class_revoke` — validated (including the `0xCA` / `0xAC` group-code interlock) and folded into device state by the post-verify commit | Consulting the accumulated state at boot to reject a revoked algorithm class or an unmet cohort — needs multi-cohort signature support |
| Public key / signature encodings | Raw bytes (`0x02`, the default) for every algorithm; ASN.1 DER (`0x01`) for RSA public keys (PKCS#1 `RSAPublicKey`) and ECDSA signatures. Each value is bounded by its `*_size_classic` field | Vendor-defined encodings (`0x03`) |
| Verifier-key entry | — | `use_verifier_key` and every `verifier_*` field |
| Co-signer entries | — | `co_signers: [...]` and every `co_signer_*` field |

Configs that trigger a deferred feature fail fast with a single-line error of
the form `error: OCA feature deferred to future pass: <feature> (field <field>)`
within one second of tool invocation.

### Payload encryption

Set `encrypted_payload: 1` (secure boot required) to encrypt the whole payload
(table of contents + all images) with **AES-256-CBC** or **AES-128-CBC**, selected
by `encryption_type`. Set it explicitly; when omitted it defaults to the stronger
AES-256-CBC. The AES key is derived from a supplied **pre-shared secret** via the
NIST SP 800-108r1 Counter Mode (HMAC-SHA-256) key-derivation function — the secret
is never used directly as the key and never written into the manifest. Applies
identically to the `oca-classic` and `oca-pqc` variants. See
[configs/oca_encrypted_example.yaml](configs/oca_encrypted_example.yaml).

```yaml
secure_boot: 1
encrypted_payload: 1
encryption_type: 0x02                      # 0x02 = AES-256-CBC (default), 0x01 = AES-128-CBC
encryption_key_derivation_function: 0x0001 # SP 800-108r1 CTR HMAC-SHA-256
encryption_shared_secret_select: 1         # which provisioned secret (indices start at 1)
encryption_secret: "<64 hex chars>"        # 32-byte secret; OR encryption_secret_file: <path>
encryption_iv: "<32 hex chars>"            # 16-byte IV — optional, generated if omitted
encryption_kdf_input: "<128 hex chars>"    # 64-byte KDF context — optional, generated if omitted
```

`encryption_shared_secret_select` is an index recorded in the manifest that
tells the consumer which of its provisioned pre-shared secrets to feed the KDF;
it is metadata, not a decryption input.

**Key-derivation input block** The KDF does *not*
run over `encryption_kdf_input` alone. It runs over a fixed **192-byte structured
input block** — `header(32) ‖ label(32) ‖ context(64) ‖ entropy(64)` — where the
header carries fixed key-purpose metadata with the derived-key length in its
`out_bits` field, the label is the ASCII string `KM_CLASS_BL` (null-padded), the
context is the manifest's full 64-byte `encryption_kdf_input` field, and the
entropy region is zero. The PRF stream is
`HMAC-SHA-256(secret, be16(i) ‖ block ‖ be16(L))` truncated to `L/8` bytes, with
the 16-bit counter `i` starting at 1 and `L` the derived-key length in bits (256
for AES-256-CBC, 128 for AES-128-CBC). This reproduces the OCA Key Manager
`PREPARE_BL_DECRYPT_KEY` flow byte-for-byte; a producer and consumer that do not
assemble these bytes identically cannot exchange an encrypted payload. The
derivation binds no device state, so it is reproducible in every lifecycle state.
Known-answer vectors are locked down in
[tests/test_oca_kdf_kat.py](tests/test_oca_kdf_kat.py).

The IV and KDF input may be supplied for a byte-reproducible build, or omitted
to have the tool generate random values and record them in a side-car file
`encrypt_inputs_<last 8 hex of the manifest hash>.json` (the side-car holds only
those public inputs, never the secret). `payload_hash` covers the stored
ciphertext; `payload_hash_chain` covers the plaintext.

The consumer verifies `payload_hash` over the ciphertext **before** decrypting
(authenticate-then-decrypt), then decrypts and confirms `payload_hash_chain`
over the recovered plaintext. A memory-constrained consumer may decrypt **in
place**, over the ciphertext, so an encrypted payload needs one buffer rather
than two — see [in-place payload
decryption](validators/oca/README.md#in-place-payload-decryption-constrained-targets).
With the host validator:

```bash
oca-validate --manifest bundle.bin \
    --payload-secret <64 hex chars> \    # or [<slot>:]<hex>, or --payload-secret-file
    --payload-out recovered_payload.bin  # decrypted payload on success
```

Supply one secret per provisioned slot with `--payload-secret <slot>:<hex>`
(a bare secret is slot 1); the validator picks the one matching the manifest's
`encryption_shared_secret_select`.

Where the key material comes from is an *encryption authority* abstraction
(`encryption_authority`, default `local`); `aws` and `hsm` are reserved for a
future pass and rejected today rather than shipping a partial implementation.

### Secure-boot device state (ROOT-key revocation & anti-rollback)

Under secure boot, the manifest carries device-state controls that a consumer
enforces at boot and folds into its own write-once state (fuses/OTP) after a
successful, authenticated verification. See
[configs/oca_secure_boot_production_example.yaml](configs/oca_secure_boot_production_example.yaml)
for a full worked example.

```yaml
secure_boot: 1
signature_type: 0x01                # RSA-3072 PKCS#1 v1.5 / SHA-256
signing_key_file: "<path to signing key>"
public_key_select_classic: 0x01     # authorize the signing key (group 1, slot 0)
public_key_classic_revoke: 0x06     # revoke retired/compromised slots 1 and 2
manifest_security_version: 0x07     # 128-bit posture flags (one bit per resolved issue)
manifest_security_control: 0x00     # 0x00 = production; 0x3F suppresses device-state updates (dev)
signature_cohort_enforce: 0x01      # ROOT key must present a classical signature
signature_class_revoke: 0x00        # no algorithm class revoked
```

- **ROOT-key revocation** — `public_key_select_classic` authorizes keys and
  `public_key_classic_revoke` marks slots revoked (both 128-bit bitmaps: 7 groups
  of 16, top 16 bits reserved). The validator refuses to use a selected key that
  is revoked — in the manifest **or** the device's stored revocation state —
  *before* verifying the signature. Do not revoke the slot you select.
- **Anti-rollback security version** — `manifest_security_version` is a 128-bit
  field of independent posture flags (not a linear counter). The validator rejects
  a manifest whose flags are not a **bit-superset** of the device's stored value,
  so an older manifest missing a flag the device already recorded is refused as a
  rollback.
- **Signature posture** — `signature_cohort_enforce` and `signature_class_revoke`
  are device control registers for managing the post-quantum transition. The first
  says which signature cohorts (classical, PQC, or both) each signed entity must
  present, with a 4-bit nibble per entity so the ROOT key, verifier key, and each
  co-signer advance independently. The second disables algorithm classes outright,
  and each half carries a group code — `0xCA` classical, `0xAC` PQC — that must be
  written **exactly** or left `0x00`; a fragment is rejected, because these updates
  accumulate by OR and fragments from separate manifests would otherwise add up to
  a group-wide revocation no single manifest declared. Neither register affects the
  boot that carries it: both take effect from the next boot onward. Setting both
  group codes under enforced secure boot bricks the device.
- **Device-state updates** — after a successful verification the consumer OR-s the
  manifest's revocations, security-version flags, and signature posture into its
  stored state (bits only ever turn on). The six disable bits in
  `manifest_security_control` suppress those updates: leave `0x00` for production
  so the device advances on each boot; set `0x3F` on development manifests to avoid
  burning fuses while iterating.

These checks engage whenever secure boot is in force — the `secure_boot` enable
bit **or** a device-reported signal (lifecycle/fuses), defaulting to in-force when
neither is present — and share that determination with signature verification.
They are validated end-to-end by [`validators/oca/`](validators/oca/);
PQC ROOT-key revocation is reserved for the PQC signature-verification pass.

### Usage-constraints control plane

The `usage_constraints` block gates firmware-to-device matching. Producers
can either set the raw `selector_bits` integer directly or use the ergonomic
shapes that auto-derive it:

- **Per-byte identity selection** — pick individual `chiplet_id` / `package_id`
  / `system_id` bytes via sparse mapping (`{0: 0xDE, 1: 0xAD}`) or a dense
  `value` + `selected`/`mask` form. Unselected positions auto-fill with `0xA5`.
- **Lifecycle named-state lists** — declare permitted lifecycle states by
  name (`[TEST_DEV, PROD_END]`); the packer OR's the bits and sets the
  per-level enable bit in `selector_bits[96..98]`.
- **Version-range halves** — independently-optional `min` / `max` halves per
  level (`chiplet`/`package`/`system`); enable bits set in `selector_bits[99..104]`.
- **Demotion control** — accepts either a 16-bit raw integer or a list of
  vendor-defined flags (`BL1_DEMOTION_VALID`, `BL1_DEMOTION_ENABLE`,
  `BL2_DEMOTION_VALID`, `BL2_DEMOTION_ENABLE`).

Combining raw `selector_bits` with an ergonomic-shaped field is rejected with
a single-line error that names both inputs and embeds the equivalent
`selector_bits` value the ergonomic fields would have produced. Legacy
hex-string identity values continue to compose with `selector_bits` for
backward compatibility. See
[examples/oca_classic_basic/README.md](examples/oca_classic_basic/README.md#usage-constraints-control-plane)
for full recipes and the combined example at
[configs/oca_classic_control_plane_example.yaml](configs/oca_classic_control_plane_example.yaml).

### Consumer-side validator (C library + host CLI)

The Python packer produces manifests; the C validator under
[`validators/oca/`](validators/oca/) reads them back the same
way the silicon's on-chip parser will. A single freestanding library plus
a host CLI (`oca-validate`) that wires OpenSSL 3 in for cryptography and
takes hardware-identity values via command-line flags. Beyond the PASS/FAIL
verdict, the library exposes the payload table-of-contents through
`oca_payload_region()` / `oca_toc_info()` / `oca_toc_image_at()`, so a consumer
gets each image's `load_addr`, `entry_point`, type, and version for staging and
execution (`oca-validate --list-images` prints them). One library and one
binary handle every variant — the manifest magic selects Classic or PQC at
runtime; integrators never pick a variant when calling the library. `make -C
validators/oca check` packs the canonical fixtures via the packer
and round-trips each through the C validator — drift between producer
and consumer fails CI loudly via the layout-sync gate documented in
[`validators/oca/README.md`](validators/oca/README.md).

A consumer that must **never** accept a given variant (for example a pre-PQC
boot ROM) can compile the other out at build time. `make -C
validators/oca classic-only` builds with PQC excluded and `pqc-only`
with Classic excluded (`both`, the default, accepts every variant); an
excluded variant is then reported as an unsupported-variant failure rather
than validated. This is the only build-time variant choice — there is no
per-variant source fork.

## Combined deployable images

Multiple manifest+payload bundles can be assembled into a single flat deployable
binary — the full image that initializes a device's flash for an initial
deployment — via the **`oca-combined` packaging mode**, for N software "banks"
(an A/B pair, a primary/secondary/recovery triplet, etc.).

### OCA combined packaging mode

`oca-combined` is a **packaging mode, not a manifest format** — it is *not* a third OCA
variant alongside `oca-classic` / `oca-pqc`, and it builds no manifest of its own. It
places already-built OCA bundles (each with its own `oca-classic` or `oca-pqc` config,
signed independently) at the offsets you choose and checks that nothing overlaps.
Building a single bank on its own (the ordinary single-bundle flow) remains the path
for field updates.

Opt in with `manifest_format: oca-combined`. The configuration lists each bank as a named
combo referencing that bank's own `oca-classic` (or `oca-pqc`) config, plus optional
opaque data regions (such as storage-device parameters or device-state metadata):

```yaml
manifest_format: oca-combined        # packaging mode — assembles the banks below
name: "Full provisioning image"      # optional, descriptive
total_size: 0x2000000                # optional; validate fit + pad to this size
pad_byte: 0xFF                       # optional; gap fill (default 0xFF, flash-erased)

combos:
  - name: primary
    config: configs/bank_a.yaml      # an oca-classic or oca-pqc manifest config
    manifest_offset: 0x0             # absolute byte offset of the manifest body
    payload_offset: 0x1000           # single base, or a list of per-image offsets

  - name: secondary
    config: configs/bank_b.yaml
    manifest_offset: 0x800000
    payload_offset: 0x801000

auxiliary_regions:                   # optional raw blobs, copied verbatim
  - name: storage_params
    path: configs/storage_params.bin
    offset: 0x1F00000
```

Build it through the same entry point used for single bundles:

```bash
python -m tt_boot_manifest.pack_images \
    --config configs/oca_combined_example.yaml \
    --out   out/full_image.bin \
    -v
```

Key properties:

- **Offsets are absolute** byte positions within the output image.
- **No overlaps**: any two regions (manifest body, payload, or auxiliary blob) that
  would collide cause the build to fail with a single-line error naming both regions —
  and no output file is written.
- **Isolated assembly**: a bank built on its own is byte-identical to that same bank
  inside the combined image, so a single-bank build doubles as a field-update artifact.
  Signed manifest bytes are never modified.
- **The configuration is the map**: the image is a flat binary with no embedded index or
  header; this YAML describes how it is partitioned.

A runnable example lives at
[configs/oca_combined_example.yaml](configs/oca_combined_example.yaml).

## YAML Configuration

Firmware bundles are defined by a YAML config. The first thing a config establishes is
**which manifest format** to build — the field is required:

```yaml
manifest_format: oca-classic    # or oca-pqc / oca-combined
```

References:

- [OCA Manifest Generation](#oca-manifest-generation) above, and the runnable examples
  [configs/oca_classic_example.yaml](configs/oca_classic_example.yaml),
  [configs/oca_encrypted_example.yaml](configs/oca_encrypted_example.yaml), and
  [configs/oca_secure_boot_production_example.yaml](configs/oca_secure_boot_production_example.yaml).
- The byte-level field reference is the specification:
  [specifications/oca/boot-manifest.adoc](specifications/oca/boot-manifest.adoc).

## Using the Lower-Level API

For more control, the packer exposes a lower-level entry point (the
`pack_images` CLI routes to it by `manifest_format`):

```python
from tt_boot_manifest.utils import load_config
from tt_boot_manifest.oca.entry import pack_oca_bundle

config = load_config("configs/oca_classic_example.yaml")  # manifest_format: oca-classic | oca-pqc
bundle = pack_oca_bundle(config)               # bytes: fixed-layout manifest body + PTOC payload
open("out/oca_classic.bin", "wb").write(bundle)
```

`pack_oca_bundle()` returns the complete bundle (manifest body followed by the payload)
for the variant named by `manifest_format`.

No release keys, key digests, or pre-signed manifests are stored in this repository —
obtain them from the signing authority for your program. The keys under
[tests/signing_keys/](tests/signing_keys/) are **development test keys only** and must
never be used for a production build.

## Building the Specification PDF

The specification is written in AsciiDoc. The top-level `Makefile` renders it to
PDF with **asciidoctor-pdf**, which must be on `PATH` — see
[Prerequisites](#prerequisites). Nothing else in the repository requires it, so a
clone without it is fully usable for everything except this target.

```bash
make spec-pdf   # or just `make` — it is the default target
                # -> build/oca-boot-manifest.pdf

make clean      # remove build/
make help       # list targets and variables
```

The output lands in `build/` (already git-ignored). The tool, output directory,
and flags are overridable without editing the Makefile:

```bash
make spec-pdf ASCIIDOCTOR_PDF=/path/to/asciidoctor-pdf
make spec-pdf BUILD_DIR=/tmp/spec-out
```

Page setup comes from [specifications/theme.yml](specifications/theme.yml), which
mirrors the theme used by the OCA harness documentation build so the spec PDF
matches the consumer-side documentation set. It extends the stock asciidoctor-pdf
theme and vendors no fonts, so the gem is the only dependency.

CI builds the PDF on every push and pull request (the `Specification PDF` job in
[.github/workflows/ci.yml](.github/workflows/ci.yml)), asserts that the rendered
document is complete, and uploads it as a build artifact — so a specification
change can be reviewed as a PDF straight from the pull request.

Two things to know before changing the flags:

- The specification source is written to be **included** in the larger OCA system
  architecture specification: its headings start at level 3 and it carries no
  document title. The build promotes headings by two levels (`-d book
  -a leveloffset=-2`) so the standalone PDF gets a title page and a contents page
  instead of an untitled pile of nested sections.
- asciidoctor-pdf cannot split a table cell across a page boundary — a cell taller
  than one page is **truncated**, dropping specification text, and the tool still
  exits 0. The build passes `--failure-level=ERROR` to turn that into a build
  failure, and the theme's type sizes keep the largest field Description cells
  (`manifest_security_control` is the worst) on a single page. If a future edit
  outgrows that, the build fails instead of publishing a hole.

## Testing

### Running Tests

The test suite validates packaging logic, signature generation, encryption, and manifest structure. Make sure you have installed the package with development dependencies first:

```bash
# Install with test dependencies
pip install -e ".[dev,aws]"

# Run all tests (AWS tests skip automatically without credentials)
pytest -vvv

# Run all tests excluding AWS tests explicitly
pytest -vvv -m "not aws"

# Run specific test file
pytest -vvv tests/test_oca_signing.py

# Run AWS KMS tests only (requires AWS credentials; refresh them with `aws-sso`)
pytest -vvv -m aws

# Run with coverage report
pytest -vvv --cov=tt_boot_manifest --cov-report=html
```

A plain `pytest` run needs no host setup beyond the Python dependencies: the OCA
C-validator tests skip cleanly when a C toolchain, `make`, or `pkg-config` is absent.

### Test Organization

Tests are grouped by the side they exercise:

**Shared infrastructure:**
- **`tests/test_manifest_signing.py`** — signing-key handling + signature generation/verification
- **`tests/conftest.py`** — pytest configuration

**Python producer:**
- **`tests/test_oca_*.py`** — manifest body / TOC, signing, encryption, PQC, combined, determinism, and format dispatch
- **`tests/test_oca_example_configs.py`** — builds each `configs/oca_*.yaml` example and validates the manifest output in pure Python (framing, `manifest_hash` recompute, signature) — no C toolchain needed

**C consumer/validator:**
- **`tests/test_oca_c_validator_integration.py`** — packs fixtures and round-trips them through the compiled `oca-validate` CLI (skips if `make`/`pkg-config` are unavailable)
- **`tests/test_oca_c_validator_layout_sync.py`** — fails on any producer↔consumer layout drift
- `make -C validators/oca check` — the validator's own C unit tests + fixture round-trips (see [validators/oca/README.md](validators/oca/README.md))

Tests use the installed `tt_boot_manifest` package, so any changes to source files require the package to be installed/reinstalled (use `pip install -e .` for development mode).

## Secure Boot and Code-Signing

### What is Secure Boot?

Secure boot ensures that only authorized firmware can execute on the device. When enabled:

1. Boot ROM loads the manifest from SPI flash
2. Boot ROM verifies the manifest signature using a public key
3. If signature is valid, Boot ROM verifies payload integrity
4. Boot ROM loads and executes the verified firmware
5. If verification fails, Boot ROM falls back to its recovery strategy (e.g. another bank of a combined image) or halts
6. Verified firmware can extend secure boot to additional images by performing similar verification steps

### Signature Types

**RSA-3072 (`signature_type: 0x01`)**
- 3072-bit RSA keys with PKCS#1 v1.5 padding
- SHA-256 digest
- 384-byte signatures
- Larger signature and key sizes, faster verification
- Used by bootROM exclusively

**ECC P-256 (`signature_type: 0x05`)**
- NIST P-256 curve (secp256r1)
- ECDSA with deterministic signing (RFC 6979)
- SHA-256 digest
- 64-byte signatures (32-byte r + 32-byte s Big Ints)
- Smaller signature and key sizes, higher security

## License

Apache-2.0 — see [LICENSE](LICENSE).

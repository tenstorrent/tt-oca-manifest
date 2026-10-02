<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc. -->
# OCA-Classic Basic Example

A runnable walkthrough for the OCA-classic packer: build a minimal non-secure
bundle from a YAML config, then independently verify the byte-level invariants
of the manifest.

## Files

- `config.yaml` — minimal OCA-classic YAML for a single-payload non-secure bundle.
- `dummy_image.bin` — tiny placeholder image referenced by `config.yaml`.
- `verify.py` — independent verification of the generated bundle's byte-level
  invariants (magic, length, trailer, recomputable `manifest_hash`). The same
  script also has a `verify_signature()` helper for the signed-bundle scenario
  — see comments in the file.

## Prerequisites

Install the package from the repository root:

```bash
pip install -e ".[dev]"
```

## Generate the bundle

Run from the **repository root** so that the relative paths in `config.yaml`
resolve:

```bash
python -m tt_boot_manifest.pack_images \
    --config examples/oca_classic_basic/config.yaml \
    --out out/oca_classic_demo.bin \
    -v
```

Expected output (under `-v`):

```
pack_images: INFO: oca-classic: manifest_identifier=DEMO1 timestamp: 1764633600
pack_images: INFO: oca-classic: wrote 4412 bytes to out/oca_classic_demo.bin
```

## Verify the bundle independently

```bash
python examples/oca_classic_basic/verify.py out/oca_classic_demo.bin
```

Expected output:

```
OK: OCA magic, length, trailer, and manifest_hash all verified.
```

## What this proves

- `OCAC` magic at byte 0 — confirms the OCA-classic format selector worked.
- 4096-byte manifest body — confirms the fixed-layout header.
- `0xCA 0xCA 0xCA 0xCA` trailer at offset 3168 — confirms the signed-region
  boundary.
- `manifest_hash` field recomputes from the signed region — confirms the
  whole signed-region build path matches the contract.

## Switching to a signed bundle

To sign with a development RSA-3072 key:

1. Replace the `secure_boot: 0` line in `config.yaml` with:

   ```yaml
   secure_boot: 1
   signature_type: 0x01
   signing_authority: local
   signing_key_name: "test_dev_rom_key_0"
   signing_key_id: "1234567890"
   signing_key_file: "tests/signing_keys/rsa_private_key.f4.pem"
   public_key_select_classic: 0x01
   allow_test_signing_key: true
   ```

   `allow_test_signing_key: true` is required. The key is a development key
   committed to this repository, and the packer refuses to sign with one unless
   the config declares it, so a manifest signed with public key material cannot
   be built by accident. A real build omits that line and signs with a key from
   its signing authority; start one from
   [configs/oca_production_template.yaml](../../configs/oca_production_template.yaml).

2. Regenerate the bundle (same command).

3. In `verify.py`, uncomment the `verify_signature(bundle)` call in `main()`.
   It loads the embedded public key from the manifest, reconstructs the signed
   region, and verifies the signature with the `cryptography` library — an
   independent code path from the one that produced the signature.

## Deterministic builds

`config.yaml` pins `timestamp: 1764633600`. Generating the bundle twice
produces byte-identical output (covered by
`tests/test_oca_determinism.py::test_oca_classic_byte_identical_repeated_runs`).

## Usage-constraints control plane

Boot ROMs gate firmware-to-device matching on the `usage_constraints` block.
The packer accepts three field families, each describable either via the
ergonomic shapes below (recommended) or as a raw `selector_bits` integer.

### Per-byte identity selection

Pick exactly the chiplet/package/system bytes that must match — the packer
auto-derives the corresponding `selector_bits` bits and fills unselected
positions with `0xA5`. Each example below shows a different shape; the count
in the comment is how many bytes that example actively enables.

```yaml
usage_constraints:
  # 2 bytes enabled — sparse mapping: byte_index → byte_value.
  chiplet_id:
    0: 0xDE
    1: 0xAD

  # 3 bytes enabled — dense form with explicit selection list.
  # selector_bits[32..34] are set; the other 29 bytes of the field are 0xA5.
  package_id:
    value: [0x11, 0x22, 0x33, 0xA5, 0xA5, ..., 0xA5]   # 32 bytes
    selected: [0, 1, 2]

  # 1 byte enabled — dense form with a 32-bit selection mask.
  # mask = 0x00000001 → selector_bits[64] only.
  system_id:
    value: [0x55, 0xA5, ..., 0xA5]                     # 32 bytes
    mask: 0x00000001
```

### Lifecycle named-state lists

Pick the lifecycle states the firmware is allowed to boot into; the packer
OR's the bit values and sets the per-level enable bit. Supported tokens:
`TEST_DEV`, `PROD`, `PROD_END`, `RMA_SIP`, `RMA_CHIPLET`, `PROD_DBG_1`,
`PROD_DBG_2`.

```yaml
usage_constraints:
  lifecycle_chiplet_states: [TEST_DEV, PROD_END]   # bits 0 + 2 → 0x05
  lifecycle_package_states: [PROD]                 # bit 1     → 0x02
  # lifecycle_system_states: omitted → field is zero, enable bit clear
```

### Version-range halves

Each level (`chiplet`/`package`/`system`) accepts independently-optional
`min`/`max` halves. The packer detects which halves are present and sets the
matching enable bits in `selector_bits[99..104]`:

```yaml
usage_constraints:
  version_range_chiplet:                 # both halves → enable bits 99 + 100
    major_min: 1
    minor_min: 0
    major_max: 2
    minor_max: 255
  version_range_package:                 # min only   → enable bit 101
    major_min: 3
    minor_min: 4
  version_range_system:                  # max only   → enable bit 104
    major_max: 5
    minor_max: 6
```

### Demotion control

A 16-bit field accepting either a raw integer or a list of vendor-defined
flags. Bits 4..15 are reserved and rejected if set.

```yaml
usage_constraints:
  demotion_control: [BL1_DEMOTION_VALID, BL1_DEMOTION_ENABLE]  # bits 0 + 1 → 0x03
  # equivalent: demotion_control: 0x03
```

### Mode-conflict diagnostic

Combining a raw `selector_bits` value with any ergonomic-shaped field (a
dict-shaped ID, a list-shaped lifecycle or demotion field, or any
`version_range_*`) is rejected with a single-line error that names both
inputs and embeds the raw-equivalent value the ergonomic fields alone would
have produced. The original raw mode (`selector_bits` + a hex-string
identity) continues to work and is byte-stable.

A complete combined-recipe config lives at
`configs/oca_classic_control_plane_example.yaml`.

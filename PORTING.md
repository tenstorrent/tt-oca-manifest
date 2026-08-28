# Porting changes from tt-boot-manifest

This repository was seeded from
[tenstorrent/tt-boot-manifest](https://github.com/tenstorrent/tt-boot-manifest),
keeping the directory structure identical so that changes can be ported across
with plain `git cherry-pick`.

## Source pin

| | |
|---|---|
| Source repository | `tenstorrent/tt-boot-manifest` |
| Last synced commit | `f29291954ef29adf19bf107e759b1a4ca0cbc70c` |

Update the pin after each sync so the next port can use
`git log <pin>..tt-boot-manifest/main` to find candidate commits.

## Porting workflow

```bash
git remote add tt-boot-manifest git@github.com:tenstorrent/tt-boot-manifest.git
git fetch tt-boot-manifest
git cherry-pick -x <sha>     # OCA-scoped commits usually apply cleanly
```

Paths are unchanged relative to the source repo, so commits that touch only the
trees listed under "Identical trees" below apply without conflicts.

## Identical trees (cherry-pick cleanly)

- `specifications/oca/`
- `validators/oca/`
- `examples/oca_classic_basic/`
- `configs/oca_*.yaml`
- `src/oca/` (except `signing.py`)
- `src/utils.py`, `src/manifest_signing.py`, `src/aes128cbc.py`, `src/aes256cbc.py`
- `tests/test_oca_*.py` (except the files listed below), `tests/oca_fixtures/`, `tests/signing_keys/`

## Intentionally divergent files (expect conflicts)

| File | Divergence |
|---|---|
| `README.md` | Rewritten for this repository |
| `pyproject.toml` | Distribution name, license, trimmed dependencies and packages |
| `.github/workflows/ci.yml` | OBJDUMP pin step and llvm install removed |
| `.gitignore` | `tests/fw_images` carve-out removed |
| `src/pack_images.py` | Rewritten as a dispatch-only CLI; `manifest_format` is required |
| `src/pack_images_constants.py` | Trimmed to the constants this repo's code consumes |
| `src/__init__.py` | Docstring and `__all__` updated |
| `src/oca/signing.py` | Internal identifier renames (`_OCA_TO_INTERNAL_SIG_TYPE`, `_NON_BL1_MANIFEST_IDENTIFIER`) |
| `src/oca/validators.py` | `manifest_format` accepted set trimmed |
| `tests/conftest.py` | Trimmed to the root-anchoring core |
| `tests/test_oca_dispatch.py` | Replaced with dispatch tests for this repo's accepted formats |
| `tests/test_oca_determinism.py` | Legacy byte-identity test removed |
| `tests/test_manifest_signing.py` | Default config inlined; KMS fixture names changed |

## Intentionally absent trees

A cherry-pick that touches any of these should be rejected or trimmed before
merging: `configs/default.yaml`, `examples/basic_manifest_generation/`,
`src/spi_configs/`, `src/pack_presigned_manifests.py`, `src/dump_packed_images.py`,
`src/get_app_entry.py`, `src/efuses.py`, `src/image-config.py`,
`src/bin_to_sram_preload.py`, `src/generate-smc-sram.py`, `tools/*.c`, `tools/*.h`,
`tests/test_packing.py`, `tests/test_dump_packed_images.py`, `tests/fw_images/`,
`specs/`, `.specify/`, `.claude/`, `CLAUDE.md`.

## Gate before merging any port

Legacy-format terminology from the source repository must not enter this one:

```bash
grep -riIn 'g[r]endel' . --exclude-dir=.git
```

must return nothing (the bracketed pattern keeps this file from matching
itself), and the full test bench must pass:

```bash
python -m pytest -m "not aws"
make -C validators/oca check
```

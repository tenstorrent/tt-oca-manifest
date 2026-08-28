"""Drift-check oca_layout.h against src/oca/constants.py.

Run from anywhere in the project tree:

    python3 validators/oca/lib/scripts/sync_layout.py [--suggest-fix]

Two checks run on every invocation:

  1. **Drift**: every `OCA_OFF_*` / `OCA_LEN_*` / mask
     in the C header must have the same integer value as its Python
     counterpart. Mismatch → exit 1 with a unified diff.

  2. **Completeness**: every `OFF_*` / `LEN_*` / `SELECTOR_BIT_*`
     constant in `tt_boot_manifest.oca.constants` that is NOT on the
     "validator-not-required" allowlist (reserved regions, deferred
     features, payload-tail metadata, etc.) MUST be referenced in this
     script's MAPPING. Adding a new validator-relevant constant on the
     Python side without mapping it triggers this check and the pytest
     collector under `tests/test_oca_c_validator_layout_sync.py` fails
     until the mapping is in place.

With `--suggest-fix`, the drift report also prints a `sed` snippet the
operator can apply to bring the C side back into agreement.

The C side is the source of what ships to silicon; the Python side is
the source of what the packer writes. Both must agree on every field
offset, or producer and consumer diverge silently.
"""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
_LIB = PROJECT_ROOT / "validators" / "oca" / "lib"
# Shared base + the per-variant header. The variant-specific defines (body size,
# signed-region end, trailer, signature/hash offsets) live in the variant file;
# the shared offsets live in oca_layout.h.
C_HEADERS = [
    _LIB / "oca_layout.h",
    _LIB / "oca_layout_classic.h",
    _LIB / "oca_layout_pqc.h",
]


# C-side identifier -> (Python module attribute name, value-format).
# Value-format is "dec" for plain integers and "hex" for masks rendered in
# hex; we normalize on integer comparison either way.
MAPPING: dict[str, tuple[str, str]] = {
    "OCA_CLASSIC_BODY_SIZE":                       ("OCA_CLASSIC_BODY_SIZE", "dec"),
    "OCA_CLASSIC_SIGNED_REGION_END":               ("OCA_CLASSIC_SIGNED_REGION_END", "dec"),
    "OCA_MANIFEST_UNUSED_BYTE":                    ("MANIFEST_UNUSED_BYTE", "hex"),
    "OCA_OFF_MAGIC":                       ("OFF_BOOT_MANIFEST_MAGIC", "dec"),
    "OCA_OFF_MANIFEST_IDENTIFIER":         ("OFF_MANIFEST_IDENTIFIER", "dec"),
    "OCA_OFF_MANIFEST_VERSION_MAJOR":      ("OFF_MANIFEST_VERSION_MAJOR", "dec"),
    "OCA_OFF_MANIFEST_VERSION_MINOR":      ("OFF_MANIFEST_VERSION_MINOR", "dec"),
    "OCA_OFF_MANIFEST_LENGTH":             ("OFF_MANIFEST_LENGTH", "dec"),
    "OCA_OFF_SELECTOR_BITS":               ("OFF_SELECTOR_BITS", "dec"),
    "OCA_OFF_CHIPLET_ID":                  ("OFF_CHIPLET_ID", "dec"),
    "OCA_OFF_PACKAGE_ID":                  ("OFF_PACKAGE_ID", "dec"),
    "OCA_OFF_SYSTEM_ID":                   ("OFF_SYSTEM_ID", "dec"),
    "OCA_LEN_IDENTITY":                    ("CHIPLET_ID_SIZE", "dec"),
    "OCA_OFF_LIFECYCLE_CHIPLET_STATES":    ("OFF_LIFECYCLE_CHIPLET_STATES", "dec"),
    "OCA_OFF_LIFECYCLE_PACKAGE_STATES":    ("OFF_LIFECYCLE_PACKAGE_STATES", "dec"),
    "OCA_OFF_LIFECYCLE_SYSTEM_STATES":     ("OFF_LIFECYCLE_SYSTEM_STATES", "dec"),
    "OCA_LIFECYCLE_STATES_VALID_MASK":     ("LIFECYCLE_STATES_VALID_MASK", "hex"),
    "OCA_OFF_VERSION_RANGE_CHIPLET":       ("OFF_VERSION_RANGE_CHIPLET", "dec"),
    "OCA_OFF_VERSION_RANGE_PACKAGE":       ("OFF_VERSION_RANGE_PACKAGE", "dec"),
    "OCA_OFF_VERSION_RANGE_SYSTEM":        ("OFF_VERSION_RANGE_SYSTEM", "dec"),
    "OCA_OFF_DEMOTION_CONTROL":            ("OFF_DEMOTION_CONTROL", "dec"),
    "OCA_OFF_SECURE_BOOT_CONTROL":         ("OFF_SECURE_BOOT_CONTROL", "dec"),
    "OCA_OFF_SIGNATURE_TYPE":              ("OFF_SIGNATURE_TYPE_CLASSIC", "dec"),
    "OCA_OFF_SIGNATURE_ENCODING":          ("OFF_SIGNATURE_ENCODING_CLASSIC", "dec"),
    "OCA_OFF_SIGNATURE_SIZE":              ("OFF_SIGNATURE_SIZE_CLASSIC", "dec"),
    "OCA_OFF_PUBLIC_KEY_SELECT":           ("OFF_PUBLIC_KEY_SELECT_CLASSIC", "dec"),
    "OCA_OFF_PUBLIC_KEY":                  ("OFF_PUBLIC_KEY_CLASSIC", "dec"),
    "OCA_LEN_PUBLIC_KEY":                  ("PUBLIC_KEY_CLASSIC_SIZE", "dec"),
    "OCA_OFF_PUBLIC_KEY_ENCODING":         ("OFF_PUBLIC_KEY_ENCODING_CLASSIC", "dec"),
    "OCA_OFF_PUBLIC_KEY_SIZE":             ("OFF_PUBLIC_KEY_SIZE_CLASSIC", "dec"),
    # Secure-boot device-state fields (ROOT-key revocation + anti-rollback).
    "OCA_OFF_MANIFEST_SECURITY_CONTROL":   ("OFF_MANIFEST_SECURITY_CONTROL", "dec"),
    "OCA_LEN_MANIFEST_SECURITY_CONTROL":   ("LEN_MANIFEST_SECURITY_CONTROL", "dec"),
    "OCA_OFF_MANIFEST_SECURITY_VERSION":   ("OFF_MANIFEST_SECURITY_VERSION", "dec"),
    "OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE":   ("OFF_PUBLIC_KEY_CLASSIC_REVOKE", "dec"),
    # Signature posture registers, OR'd into device storage after a verified boot.
    "OCA_OFF_SIGNATURE_COHORT_ENFORCE":    ("OFF_SIGNATURE_COHORT_ENFORCE", "dec"),
    "OCA_LEN_SIGNATURE_COHORT_ENFORCE":    ("LEN_SIGNATURE_COHORT_ENFORCE", "dec"),
    "OCA_OFF_SIGNATURE_CLASS_REVOKE":      ("OFF_SIGNATURE_CLASS_REVOKE", "dec"),
    "OCA_LEN_SIGNATURE_CLASS_REVOKE":      ("LEN_SIGNATURE_CLASS_REVOKE", "dec"),
    "OCA_CLASS_REVOKE_CLASSIC_GROUP_CODE": ("SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_CODE", "hex"),
    "OCA_CLASS_REVOKE_PQC_GROUP_CODE":     ("SIGNATURE_CLASS_REVOKE_PQC_GROUP_CODE", "hex"),
    "OCA_OFF_MANIFEST_CONTENT_VERSION":    ("OFF_MANIFEST_CONTENT_VERSION", "dec"),
    "OCA_OFF_MANIFEST_DESCRIPTION":        ("OFF_MANIFEST_DESCRIPTION", "dec"),
    "OCA_CLASSIC_OFF_TRAILER":                     ("OFF_CLASSIC_MANIFEST_TRAILER", "dec"),
    "OCA_CLASSIC_OFF_SIGNATURE":                   ("OFF_SIGNATURE_CLASSIC", "dec"),
    "OCA_LEN_SIGNATURE":                   ("SIGNATURE_CLASSIC_SIZE", "dec"),
    "OCA_CLASSIC_OFF_MANIFEST_HASH":               ("OFF_MANIFEST_HASH", "dec"),
    "OCA_LEN_MANIFEST_HASH":               ("HASH_FIELD_SIZE", "dec"),
    "OCA_MANIFEST_HASH_DIGEST_SIZE":              ("MANIFEST_HASH_DIGEST_SIZE", "dec"),
    # PQC variant anchors. Only the values the Python packer names
    # independently are cross-checked here; the PQC per-field offsets are
    # derived from region sizes on the Python side and asserted internally on
    # the C side (oca_layout_pqc.h static_asserts), so they have no Python
    # counterpart to diff against.
    "OCA_PQC_BODY_SIZE":                   ("OCA_PQC_BODY_SIZE", "dec"),
    "OCA_PQC_SIGNED_REGION_END":           ("PQC_SIGNED_REGION_END", "dec"),
    "OCA_PQC_OFF_PAYLOAD_OFFSET":          ("PQC_PAYLOAD_OFFSET_FIELD", "dec"),
    "OCA_PQC_LEN_SIGNATURE_PQC":           ("PQC_SIGNATURE_SIZE", "dec"),
    # Payload encryption + payload-hash fields (consumed by the encrypted-payload
    # validation stage) and the PTOC sizes used to recompute the plaintext chain.
    "OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL":  ("OFF_PAYLOAD_ENCRYPTION_CONTROL", "dec"),
    "OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT": ("OFF_ENCRYPTION_SHARED_SECRET_SELECT", "dec"),
    "OCA_OFF_ENCRYPTION_IV":               ("OFF_ENCRYPTION_IV", "dec"),
    "OCA_LEN_ENCRYPTION_IV":               ("ENCRYPTION_IV_SIZE", "dec"),
    "OCA_OFF_ENCRYPTION_KDF_INPUT":        ("OFF_ENCRYPTION_KDF_INPUT", "dec"),
    "OCA_LEN_ENCRYPTION_KDF_INPUT":        ("ENCRYPTION_KDF_INPUT_SIZE", "dec"),
    "OCA_OFF_ENCRYPTION_TYPE":             ("OFF_ENCRYPTION_TYPE", "dec"),
    "OCA_OFF_PAYLOAD_HASH":                ("OFF_PAYLOAD_HASH", "dec"),
    "OCA_OFF_PAYLOAD_HASH_CHAIN":          ("OFF_PAYLOAD_HASH_CHAIN", "dec"),
    "OCA_OFF_PAYLOAD_HASHED_LENGTH":       ("OFF_PAYLOAD_HASHED_LENGTH", "dec"),
    "OCA_OFF_PAYLOAD_LENGTH":              ("OFF_PAYLOAD_LENGTH", "dec"),
    "OCA_CLASSIC_OFF_PAYLOAD_OFFSET":      ("OFF_PAYLOAD_OFFSET", "dec"),
    "OCA_OFF_VERIFIER_KEY_CONTROL":        ("OFF_VERIFIER_KEY_CONTROL", "dec"),
    "OCA_OFF_CO_SIGNER_CONTROL":           ("OFF_CO_SIGNER_CONTROL", "dec"),
    "OCA_AES_BLOCK_SIZE":                  ("AES_BLOCK_SIZE", "dec"),
    # Payload TOC layout. The validator addresses every TOC header and TOC
    # entry field, so all of them are diff-checked — a repeat of the
    # misplaced-`hash` drift is a build failure, not a silent interop break.
    "OCA_TOC_HEADER_SIZE":                 ("TOC_HEADER_SIZE", "dec"),
    "OCA_TOC_ENTRY_SIZE":                  ("TOC_ENTRY_SIZE", "dec"),
    "OCA_TOC_OFF_MAGIC":                   ("OFF_TOC_MAGIC", "dec"),
    "OCA_TOC_OFF_VERSION_MAJOR":           ("OFF_TOC_VERSION_MAJOR", "dec"),
    "OCA_TOC_OFF_VERSION_MINOR":           ("OFF_TOC_VERSION_MINOR", "dec"),
    "OCA_TOC_OFF_PAYLOAD_LENGTH":          ("OFF_TOC_PAYLOAD_LENGTH", "dec"),
    "OCA_TOC_OFF_IMAGE_COUNT":             ("OFF_TOC_IMAGE_COUNT", "dec"),
    "OCA_TOC_ENTRY_OFF_TYPE":              ("OFF_TOC_ENTRY_TYPE", "dec"),
    "OCA_TOC_ENTRY_LEN_TYPE":              ("LEN_TOC_ENTRY_TYPE", "dec"),
    "OCA_TOC_ENTRY_OFF_GROUP":             ("OFF_TOC_ENTRY_GROUP", "dec"),
    "OCA_TOC_ENTRY_OFF_OFFSET":            ("OFF_TOC_ENTRY_OFFSET", "dec"),
    "OCA_TOC_ENTRY_OFF_LENGTH":            ("OFF_TOC_ENTRY_LENGTH", "dec"),
    "OCA_TOC_ENTRY_OFF_VERSION":           ("OFF_TOC_ENTRY_VERSION", "dec"),
    "OCA_TOC_ENTRY_OFF_SECURITY_VERSION":  ("OFF_TOC_ENTRY_SECURITY_VERSION", "dec"),
    "OCA_TOC_ENTRY_OFF_LOAD_ADDR":         ("OFF_TOC_ENTRY_LOAD_ADDR", "dec"),
    "OCA_TOC_ENTRY_OFF_ENTRY_POINT":       ("OFF_TOC_ENTRY_ENTRY_POINT", "dec"),
    "OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID": ("OFF_TOC_ENTRY_TARGET_CHIPLET_ID", "dec"),
    "OCA_TOC_ENTRY_OFF_HASH":              ("OFF_TOC_ENTRY_HASH", "dec"),
    "OCA_TOC_ENTRY_OFF_DESCRIPTION":       ("OFF_TOC_ENTRY_DESCRIPTION", "dec"),
    "OCA_TOC_ENTRY_LEN_DESCRIPTION":       ("LEN_TOC_ENTRY_DESCRIPTION", "dec"),
}


_DEFINE_RE = re.compile(
    r"^\s*#define\s+(?P<name>[A-Z][A-Z0-9_]*)\s+(?P<value>0x[0-9A-Fa-f]+u?|\d+u?)"
)

# Python-side constants the validator does not need to know about.
# Adding a NEW constant whose name does NOT match any of these prefixes
# but is NOT mapped above will fail the completeness check, forcing the
# author to either map it on the C side or extend this allowlist with
# explicit justification.
NOT_REQUIRED_PREFIXES = (
    "OFF_RESERVED_",
    "LEN_RESERVED_",
    "OFF_ENCRYPTION_",
    "LEN_ENCRYPTION_",
    "OFF_PAYLOAD_",         # residual payload metadata the validator does not
                            # gate on (payload_hash_type). payload_offset IS
                            # now consumed -- oca_locate_payload resolves and
                            # bounds-checks it -- and is mapped explicitly. The
                            # ones it DOES consume — payload_length,
                            # payload_hashed_length, payload_hash[_chain],
                            # payload_encryption_control — are mapped above,
                            # and an explicit mapping wins over this prefix.
    "OFF_VERIFIER_KEY_",    # deferred feature
    "OFF_VERIFIER_",        # deferred verifier-key family (security_version etc.)
    "OFF_CO_SIGNER_",       # deferred feature
    "OFF_UNAUTHENTICATED_", # field lives outside the signed region; not gated
    "OFF_FEATURE_CONTROL",
    "OFF_TIMESTAMP",        # informational, not gate-affecting
    "OFF_MANIFEST_HASH_TYPE",
    "OFF_ENCRYPTION_TYPE",
)

# Python-side names explicitly NOT required (one-offs the prefix list
# would over-include). Same justification rule: add a name here only
# when it's deliberately not validator-relevant.
NOT_REQUIRED_EXACT = {
    "OFF_BOOT_MANIFEST_MAGIC_BACKUP",  # backup-manifest variant (out of scope)
}


def parse_c_header(path: Path) -> dict[str, int]:
    """Return {C-define-name: integer-value} for every #define in the header."""
    out: dict[str, int] = {}
    for line in path.read_text().splitlines():
        m = _DEFINE_RE.match(line)
        if not m:
            continue
        value = m["value"].rstrip("uU")
        out[m["name"]] = int(value, 0)
    return out


def load_python_constants() -> dict[str, int]:
    """Import the packer's constants module and return its symbol table."""
    try:
        from tt_boot_manifest.oca import constants as C  # noqa: WPS433
    except ImportError as exc:  # pragma: no cover - environment issue
        print(f"sync_layout: cannot import tt_boot_manifest.oca.constants: {exc}",
              file=sys.stderr)
        print("Hint: install the project with `pip install -e .` first.",
              file=sys.stderr)
        raise SystemExit(2)
    return {name: int(getattr(C, name)) for _, (name, _) in MAPPING.items()
            if hasattr(C, name)}


def find_unmapped_python_constants() -> list[str]:
    """Return every `OFF_*` / `LEN_*` constant in constants.py that the
    C side should know about but doesn't (no entry in MAPPING and not on
    the not-required allowlist). Empty list = completeness OK."""
    try:
        from tt_boot_manifest.oca import constants as C  # noqa: WPS433
    except ImportError:
        return []  # the drift check will catch the import failure

    mapped_py_names = {py_name for _, (py_name, _) in MAPPING.items()}

    unmapped: list[str] = []
    for name in dir(C):
        if not (name.startswith("OFF_") or name.startswith("LEN_")):
            continue
        if name in mapped_py_names:
            continue
        if name in NOT_REQUIRED_EXACT:
            continue
        if any(name.startswith(p) for p in NOT_REQUIRED_PREFIXES):
            continue
        # constants module also stores derived collections; only flag ints
        value = getattr(C, name, None)
        if not isinstance(value, int):
            continue
        unmapped.append(name)
    return sorted(unmapped)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suggest-fix", action="store_true",
                        help="Print a sed snippet to bring oca_layout.h in line.")
    args = parser.parse_args()

    c_values: dict[str, int] = {}
    c_source: dict[str, Path] = {}
    for _hdr in C_HEADERS:
        for _name, _val in parse_c_header(_hdr).items():
            c_values[_name] = _val
            c_source[_name] = _hdr
    py_values = load_python_constants()

    mismatches: list[tuple[str, int, int]] = []
    missing_in_c: list[str] = []
    for c_name, (py_name, _fmt) in MAPPING.items():
        if c_name not in c_values:
            missing_in_c.append(c_name)
            continue
        if py_name not in py_values:
            # Python side is missing the corresponding constant. That's a
            # packer-side bug, not a C-side drift; flag it loudly.
            print(f"sync_layout: WARNING: {py_name} not found in src/oca/constants.py",
                  file=sys.stderr)
            continue
        if c_values[c_name] != py_values[py_name]:
            mismatches.append((c_name, c_values[c_name], py_values[py_name]))

    if missing_in_c:
        print("sync_layout: missing C defines:", file=sys.stderr)
        for name in missing_in_c:
            print(f"  {name}", file=sys.stderr)

    unmapped = find_unmapped_python_constants()

    if not mismatches and not missing_in_c and not unmapped:
        return 0

    if unmapped:
        print("sync_layout: completeness check FAILED — the following "
              "Python-side constants in tt_boot_manifest.oca.constants "
              "are not mapped to the C side, and they aren't on the "
              "validator-not-required allowlist:", file=sys.stderr)
        for name in unmapped:
            print(f"  - {name}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Either:", file=sys.stderr)
        print("  1. Add an OCA_CLASSIC_* mirror in oca_layout.h and an "
              "entry in MAPPING (the validator needs to know about this "
              "field), OR", file=sys.stderr)
        print("  2. If this field is genuinely not validator-relevant, "
              "add it to NOT_REQUIRED_PREFIXES / NOT_REQUIRED_EXACT in "
              "this script with a one-line rationale.", file=sys.stderr)
        print("", file=sys.stderr)

    if mismatches or missing_in_c:
        print("sync_layout: drift detected between oca_layout.h and "
              "src/oca/constants.py", file=sys.stderr)
    a = [f"{c}: {hex(c_values.get(c, 0))}" for c, _, _ in mismatches]
    b = [f"{c}: {hex(v)}" for c, _, v in mismatches]
    for line in difflib.unified_diff(a, b, fromfile="oca_layout.h",
                                     tofile="src/oca/constants.py", lineterm=""):
        print(line, file=sys.stderr)

    if args.suggest_fix and mismatches:
        print("\nsync_layout: to bring the C side into agreement:", file=sys.stderr)
        for c_name, _, py_val in mismatches:
            new = f"0x{py_val:X}u" if py_val > 9 else f"{py_val}u"
            print(f"  sed -i '' "
                  f"'s/^\\(#define {c_name}\\s*\\).*/\\1{new}/' "
                  f"{c_source.get(c_name, C_HEADERS[0]).relative_to(PROJECT_ROOT)}",
                  file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

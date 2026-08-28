/*
 * cli_args.h — Command-line flag parser for oca-validate.
 *
 * Defines the cli_options_t struct populated by getopt_long-based parsing
 * and a helper to print the usage block on --help / on bad input.
 */

#ifndef OCA_CLI_ARGS_H
#define OCA_CLI_ARGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oca_validator.h"

/* Max pre-shared secrets the CLI can hold, one per shared-secret slot. */
#define OCA_MAX_PAYLOAD_SECRETS 8

typedef struct cli_options {
    const char *manifest_path;
    bool quiet;
    /* --list-images: after a successful validation, print the payload TOC and
     * every image entry via the oca_toc_* accessors. */
    bool list_images;
    /* --decrypt-in-place: decrypt the payload into the ciphertext buffer instead
     * of a second allocation, halving peak memory. Models what a boot ROM with
     * limited SRAM does. */
    bool decrypt_in_place;

    /* --secure-boot-disabled: model a part that is definitively not a secure-boot
     * device — a life-cycle state or a discrete disable fuse. Relaxes only the
     * requirement the DEVICE imposes: a manifest asserting secure boot is still
     * held to it, signature and all, and its encrypted payload still decrypts.
     * What changes is that a manifest with the bit clear now boots unverified. */
    bool secure_boot_disabled;

    /* --secure-boot-active: model a part that ENFORCES secure boot — input (3)
     * of the determination. Without it this host tool can only ever exercise the
     * routes a manifest settles for itself, so the device-enforced path, and the
     * per-check confirm that guards it, have no end-to-end expression.
     * Outranked by --secure-boot-disabled, exactly as on a real part. */
    bool secure_boot_active;
    /* Root-key trust anchor. --root-key-digest supplies a SHA-256 of the key's
     * modulus to authorize against; --trust-any-root-key authorizes whatever the
     * manifest carries, which is only ever right for structural checks on a
     * fixture whose key is not the point. */
    bool     trust_any_root_key;
    bool     root_key_digest_present;
    uint8_t  root_key_digest[32];

    /* Storage-image mode. When --manifest-addr is given, --manifest names a whole
     * storage image rather than a bundle: the manifest is read from that address
     * and the payload is LOCATED via payload_offset instead of being assumed to
     * follow the body. This is the staged flow a boot ROM runs. --region-base /
     * --region-limit narrow the permitted payload window (default: the whole
     * image), so a cross-bank locator can be rejected. */
    bool     storage_mode;
    int64_t  manifest_addr;
    bool     region_base_present;
    int64_t  region_base;
    bool     region_limit_present;
    int64_t  region_limit;

    /* Per-field identity bytes. `*_present` says whether the flag was
     * supplied; if false the library's identity callback returns
     * OCA_HW_UNAVAILABLE. */
    bool    chiplet_id_present;
    uint8_t chiplet_id[32];
    bool    package_id_present;
    uint8_t package_id[32];
    bool    system_id_present;
    uint8_t system_id[32];

    /* Lifecycle (one value applied to all three levels). */
    bool                  lifecycle_present;
    oca_lifecycle_token_t lifecycle_token;

    /* Per-level versions. */
    bool     version_chiplet_present;
    uint16_t version_chiplet_major;
    uint16_t version_chiplet_minor;
    bool     version_package_present;
    uint16_t version_package_major;
    uint16_t version_package_minor;
    bool     version_system_present;
    uint16_t version_system_major;
    uint16_t version_system_minor;

    /* Payload decryption (encrypted bundles). Up to OCA_MAX_PAYLOAD_SECRETS
     * 32-byte pre-shared secrets, each keyed by the manifest slot
     * (encryption_shared_secret_select) it serves; the decrypt callback feeds
     * the KBKDF with the one matching the manifest's selector. The IV and KDF
     * input come from the manifest. `payload_out_path`, when set, receives the
     * recovered plaintext on a successful validation. */
    size_t      payload_secret_count;
    uint16_t    payload_secret_slot[OCA_MAX_PAYLOAD_SECRETS];
    uint8_t     payload_secret[OCA_MAX_PAYLOAD_SECRETS][32];
    const char *payload_out_path;
} cli_options_t;

/* Returns 0 on success, 2 on usage error (caller exits 2). On success,
 * `*opt` is fully populated. On error, prints a `usage:` line to stderr. */
int cli_parse_args(int argc, char **argv, cli_options_t *opt);

/* Print the full --help block to stdout. */
void cli_print_help(void);

#endif /* OCA_CLI_ARGS_H */

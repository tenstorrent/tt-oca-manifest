/*
 * cli_args.c — getopt_long-based parser for the oca-validate CLI.
 */

#include "cli_args.h"

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Parse exactly 64 hex chars (optional 0x prefix) into a 32-byte buffer.
 * Returns 0 on success, -1 on malformed input. */
static int parse_hex32(const char *s, uint8_t out[32])
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    if (strlen(s) != 64u) {
        return -1;
    }
    for (unsigned i = 0; i < 32u; ++i) {
        int hi = hex_nibble((unsigned char)s[i * 2u + 0u]);
        int lo = hex_nibble((unsigned char)s[i * 2u + 1u]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Read a 32-byte pre-shared secret from `path`: either 32 raw bytes or a
 * hex-text file (64 hex chars, optional 0x prefix). Returns 0 on success. */
static int read_secret_file(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    uint8_t raw[131];
    size_t n = fread(raw, 1u, sizeof raw, f);
    int overflow = (fgetc(f) != EOF);  /* file larger than our buffer? */
    fclose(f);
    if (overflow) {
        return -1;
    }
    if (n == 32u) {
        memcpy(out, raw, 32u);
        return 0;
    }
    /* Hex-text path: strip trailing whitespace, then parse. */
    while (n > 0u && (raw[n - 1u] == '\n' || raw[n - 1u] == '\r'
                      || raw[n - 1u] == ' ' || raw[n - 1u] == '\t')) {
        n--;
    }
    /* One byte larger than `raw` so the NUL terminator always has room, even
     * when the file fills `raw` exactly (n == sizeof raw). */
    char tmp[sizeof raw + 1u];
    for (size_t i = 0u; i < n; ++i) {
        tmp[i] = (char)raw[i];
    }
    tmp[n] = '\0';
    return parse_hex32(tmp, out);
}

/* Split an optional decimal "<slot>:" prefix off `arg`. Sets *slot (default 1)
 * and returns the remainder (hex/path), or NULL on a malformed slot prefix.
 * A leading token is only treated as a slot when it is all decimal digits, so
 * plain hex secrets and slot-less paths pass through unchanged. */
static const char *split_slot_prefix(const char *arg, uint16_t *slot)
{
    *slot = 1u;  /* shared-secret indices start at 1 */
    const char *colon = strchr(arg, ':');
    if (colon == NULL || colon == arg) {
        return arg;
    }
    for (const char *p = arg; p < colon; ++p) {
        if (*p < '0' || *p > '9') {
            return arg;  /* not a slot prefix */
        }
    }
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (end != colon || v < 0 || v > 0xFFFF) {
        return NULL;
    }
    *slot = (uint16_t)v;
    return colon + 1;
}

/* Append a (slot, secret) entry. Returns 0 on success, -1 when full. */
static int add_payload_secret(cli_options_t *opt, uint16_t slot,
                              const uint8_t secret[32])
{
    if (opt->payload_secret_count >= OCA_MAX_PAYLOAD_SECRETS) {
        return -1;
    }
    opt->payload_secret_slot[opt->payload_secret_count] = slot;
    memcpy(opt->payload_secret[opt->payload_secret_count], secret, 32u);
    opt->payload_secret_count++;
    return 0;
}

static int parse_version(const char *s, uint16_t *out_major, uint16_t *out_minor)
{
    char *end = NULL;
    long major = strtol(s, &end, 10);
    if (end == s || *end != '.' || major < 0 || major > 0xFFFF) {
        return -1;
    }
    const char *minor_s = end + 1;
    char *end2 = NULL;
    long minor = strtol(minor_s, &end2, 10);
    if (end2 == minor_s || *end2 != '\0' || minor < 0 || minor > 0xFFFF) {
        return -1;
    }
    *out_major = (uint16_t)major;
    *out_minor = (uint16_t)minor;
    return 0;
}

static int parse_lifecycle(const char *s, oca_lifecycle_token_t *out)
{
    struct { const char *name; oca_lifecycle_token_t tok; } table[] = {
        {"TEST_DEV",    OCA_LIFECYCLE_TEST_DEV},
        {"PROD",        OCA_LIFECYCLE_PROD},
        {"PROD_END",    OCA_LIFECYCLE_PROD_END},
        {"RMA_SIP",     OCA_LIFECYCLE_RMA_SIP},
        {"RMA_CHIPLET", OCA_LIFECYCLE_RMA_CHIPLET},
        {"PROD_DBG_1",  OCA_LIFECYCLE_PROD_DBG_1},
        {"PROD_DBG_2",  OCA_LIFECYCLE_PROD_DBG_2},
    };
    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); ++i) {
        if (strcmp(s, table[i].name) == 0) {
            *out = table[i].tok;
            return 0;
        }
    }
    return -1;
}

void cli_print_help(void)
{
    fputs(
        "usage: oca-validate --manifest <path> [flags]\n"
        "\n"
        "Validate an OCA boot manifest against a set of hardware values\n"
        "supplied on the command line.\n"
        "\n"
        "Required:\n"
        "  --manifest <path>           path to a bundle: the manifest body\n"
        "                              followed by its payload (the payload is\n"
        "                              required - validation covers it)\n"
        "\n"
        "Optional hardware flags (absent → callback reports UNAVAILABLE):\n"
        "  --chiplet-id <hex64>        32-byte chiplet identity\n"
        "  --package-id <hex64>        32-byte package identity\n"
        "  --system-id  <hex64>        32-byte system identity\n"
        "  --lifecycle <token>         one of TEST_DEV, PROD, PROD_END,\n"
        "                              RMA_SIP, RMA_CHIPLET, PROD_DBG_1,\n"
        "                              PROD_DBG_2 (same value used for\n"
        "                              all three levels)\n"
        "  --version-chiplet <M.m>     chiplet-level current version\n"
        "  --version-package <M.m>     package-level current version\n"
        "  --version-system  <M.m>     system-level current version\n"
        "\n"
        "Encrypted payload (secure-boot bundles):\n"
        "  --payload-secret [<slot>:]<hex64>   32-byte pre-shared secret (KBKDF\n"
        "                              base key); optional <slot> matches the\n"
        "                              manifest's encryption_shared_secret_select\n"
        "                              (repeatable; default slot 1)\n"
        "  --payload-secret-file [<slot>:]<p>  read the secret from a file (raw/hex)\n"
        "  --payload-out <path>        write the decrypted payload here on PASS\n"
        "  --decrypt-in-place          decrypt into the ciphertext buffer rather\n"
        "                              than a second allocation (halves peak\n"
        "                              memory; what a constrained ROM does)\n"
        "  --trust-any-root-key        authorize whatever ROOT key the manifest\n"
        "                              carries (structural checks only)\n"
        "  --root-key-digest HEX64     authorize only a key whose modulus has\n"
        "                              this SHA-256\n"
        "  --secure-boot-active        report the part as ENFORCING secure\n"
        "                              boot (device fuse/life-cycle state).\n"
        "  --secure-boot-disabled      report the part as definitively NOT a\n"
        "                              secure-boot device (life-cycle state or a\n"
        "                              disable fuse). Relaxes only what the DEVICE\n"
        "                              requires: a manifest asserting secure boot\n"
        "                              is still verified and still decrypts its\n"
        "                              payload; a manifest with the bit clear now\n"
        "                              boots unverified\n"
        "\n"
        "Storage-image mode (the staged flow a boot ROM runs):\n"
        "  --manifest-addr <hex>       treat --manifest as a whole storage image and\n"
        "                              read the manifest from this address; the\n"
        "                              payload is then LOCATED via payload_offset\n"
        "                              rather than assumed to follow the body\n"
        "  --region-base <hex>         lowest address the payload may occupy\n"
        "                              (default 0)\n"
        "  --region-limit <hex>        one past the highest (default: image size).\n"
        "                              Narrow these to one bank so a cross-bank\n"
        "                              payload_offset is rejected\n"
        "\n"
        "Other:\n"
        "  --list-images               on PASS, print the payload TOC header and\n"
        "                              each image entry (type, offset, length,\n"
        "                              load_addr, entry_point, version)\n"
        "  --quiet                     suppress the PASS line on stdout\n"
        "  --help                      print this help and exit 0\n"
        "\n"
        "Exit codes: 0 = PASS, 1 = FAIL, 2 = usage error.\n",
        stdout);
}

enum {
    LO_MANIFEST = 1000,
    LO_CHIPLET, LO_PACKAGE, LO_SYSTEM,
    LO_LIFECYCLE,
    LO_VC, LO_VP, LO_VS,
    LO_PAYLOAD_SECRET, LO_PAYLOAD_SECRET_FILE, LO_PAYLOAD_OUT,
    LO_LIST_IMAGES, LO_DECRYPT_IN_PLACE, LO_SECURE_BOOT_DISABLED,
    LO_SECURE_BOOT_ACTIVE,
    LO_TRUST_ANY_ROOT_KEY,
    LO_ROOT_KEY_DIGEST,
    LO_MANIFEST_ADDR, LO_REGION_BASE, LO_REGION_LIMIT,
    LO_QUIET, LO_HELP,
};

static struct option long_opts[] = {
    {"manifest",         required_argument, NULL, LO_MANIFEST},
    {"chiplet-id",       required_argument, NULL, LO_CHIPLET},
    {"package-id",       required_argument, NULL, LO_PACKAGE},
    {"system-id",        required_argument, NULL, LO_SYSTEM},
    {"lifecycle",        required_argument, NULL, LO_LIFECYCLE},
    {"version-chiplet",  required_argument, NULL, LO_VC},
    {"version-package",  required_argument, NULL, LO_VP},
    {"version-system",   required_argument, NULL, LO_VS},
    {"payload-secret",      required_argument, NULL, LO_PAYLOAD_SECRET},
    {"payload-secret-file", required_argument, NULL, LO_PAYLOAD_SECRET_FILE},
    {"payload-out",         required_argument, NULL, LO_PAYLOAD_OUT},
    {"list-images",      no_argument,       NULL, LO_LIST_IMAGES},
    {"decrypt-in-place", no_argument,       NULL, LO_DECRYPT_IN_PLACE},
    {"secure-boot-disabled", no_argument,   NULL, LO_SECURE_BOOT_DISABLED},
    {"secure-boot-active",   no_argument,   NULL, LO_SECURE_BOOT_ACTIVE},
    {"trust-any-root-key",   no_argument,       NULL, LO_TRUST_ANY_ROOT_KEY},
    {"root-key-digest",      required_argument, NULL, LO_ROOT_KEY_DIGEST},
    {"manifest-addr",    required_argument, NULL, LO_MANIFEST_ADDR},
    {"region-base",      required_argument, NULL, LO_REGION_BASE},
    {"region-limit",     required_argument, NULL, LO_REGION_LIMIT},
    {"quiet",            no_argument,       NULL, LO_QUIET},
    {"help",             no_argument,       NULL, LO_HELP},
    {0, 0, 0, 0},
};

int cli_parse_args(int argc, char **argv, cli_options_t *opt)
{
    memset(opt, 0, sizeof(*opt));
    /* Silence getopt's own error messages — we own the error UX. */
    opterr = 0;

    int c;
    while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (c) {
            case LO_MANIFEST:
                opt->manifest_path = optarg;
                break;
            case LO_CHIPLET:
                if (parse_hex32(optarg, opt->chiplet_id) != 0) {
                    fprintf(stderr, "usage: --chiplet-id requires 64 hex chars\n");
                    return 2;
                }
                opt->chiplet_id_present = true;
                break;
            case LO_PACKAGE:
                if (parse_hex32(optarg, opt->package_id) != 0) {
                    fprintf(stderr, "usage: --package-id requires 64 hex chars\n");
                    return 2;
                }
                opt->package_id_present = true;
                break;
            case LO_SYSTEM:
                if (parse_hex32(optarg, opt->system_id) != 0) {
                    fprintf(stderr, "usage: --system-id requires 64 hex chars\n");
                    return 2;
                }
                opt->system_id_present = true;
                break;
            case LO_LIFECYCLE: {
                oca_lifecycle_token_t tok = OCA_LIFECYCLE_UNKNOWN;
                if (parse_lifecycle(optarg, &tok) != 0) {
                    fprintf(stderr,
                            "usage: --lifecycle requires one of "
                            "TEST_DEV, PROD, PROD_END, RMA_SIP, RMA_CHIPLET, "
                            "PROD_DBG_1, PROD_DBG_2 (got %s)\n", optarg);
                    return 2;
                }
                opt->lifecycle_present = true;
                opt->lifecycle_token = tok;
                break;
            }
            case LO_VC:
                if (parse_version(optarg, &opt->version_chiplet_major,
                                  &opt->version_chiplet_minor) != 0) {
                    fprintf(stderr, "usage: --version-chiplet requires <M.m>\n");
                    return 2;
                }
                opt->version_chiplet_present = true;
                break;
            case LO_VP:
                if (parse_version(optarg, &opt->version_package_major,
                                  &opt->version_package_minor) != 0) {
                    fprintf(stderr, "usage: --version-package requires <M.m>\n");
                    return 2;
                }
                opt->version_package_present = true;
                break;
            case LO_VS:
                if (parse_version(optarg, &opt->version_system_major,
                                  &opt->version_system_minor) != 0) {
                    fprintf(stderr, "usage: --version-system requires <M.m>\n");
                    return 2;
                }
                opt->version_system_present = true;
                break;
            case LO_PAYLOAD_SECRET: {
                uint16_t slot;
                const char *hex = split_slot_prefix(optarg, &slot);
                uint8_t secret[32];
                if (hex == NULL || parse_hex32(hex, secret) != 0) {
                    fprintf(stderr, "usage: --payload-secret requires "
                                    "[<slot>:]<64 hex chars>\n");
                    return 2;
                }
                if (add_payload_secret(opt, slot, secret) != 0) {
                    fprintf(stderr, "usage: too many --payload-secret entries "
                                    "(max %d)\n", OCA_MAX_PAYLOAD_SECRETS);
                    return 2;
                }
                break;
            }
            case LO_PAYLOAD_SECRET_FILE: {
                uint16_t slot;
                const char *path = split_slot_prefix(optarg, &slot);
                uint8_t secret[32];
                if (path == NULL || read_secret_file(path, secret) != 0) {
                    fprintf(stderr, "usage: --payload-secret-file requires "
                                    "[<slot>:]<path> (32 raw bytes or 64 hex chars)\n");
                    return 2;
                }
                if (add_payload_secret(opt, slot, secret) != 0) {
                    fprintf(stderr, "usage: too many --payload-secret entries "
                                    "(max %d)\n", OCA_MAX_PAYLOAD_SECRETS);
                    return 2;
                }
                break;
            }
            case LO_PAYLOAD_OUT:
                opt->payload_out_path = optarg;
                break;
            case LO_LIST_IMAGES:
                opt->list_images = true;
                break;
            case LO_DECRYPT_IN_PLACE:
                opt->decrypt_in_place = true;
                break;
            case LO_SECURE_BOOT_DISABLED:
                opt->secure_boot_disabled = true;
                break;
            case LO_TRUST_ANY_ROOT_KEY:
                opt->trust_any_root_key = true;
                break;
            case LO_ROOT_KEY_DIGEST:
                if (parse_hex32(optarg, opt->root_key_digest) != 0) {
                    fprintf(stderr, "usage: --root-key-digest wants 64 hex digits\n");
                    return false;
                }
                opt->root_key_digest_present = true;
                break;
            case LO_SECURE_BOOT_ACTIVE:
                opt->secure_boot_active = true;
                break;
            case LO_MANIFEST_ADDR:
                opt->storage_mode = true;
                opt->manifest_addr = (int64_t)strtoll(optarg, NULL, 0);
                break;
            case LO_REGION_BASE:
                opt->region_base_present = true;
                opt->region_base = (int64_t)strtoll(optarg, NULL, 0);
                break;
            case LO_REGION_LIMIT:
                opt->region_limit_present = true;
                opt->region_limit = (int64_t)strtoll(optarg, NULL, 0);
                break;
            case LO_QUIET:
                opt->quiet = true;
                break;
            case LO_HELP:
                cli_print_help();
                exit(0);
            default:
                fprintf(stderr, "usage: unknown or malformed flag\n");
                return 2;
        }
    }

    if (opt->manifest_path == NULL) {
        fprintf(stderr, "usage: --manifest <path> is required\n");
        return 2;
    }
    return 0;
}

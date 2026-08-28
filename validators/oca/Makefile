# OCA validator build orchestration (format-agnostic).
#
# A single library and a single binary handle every OCA format variant; the
# format-specific dispatch happens inside the library based on the manifest
# magic bytes. OCA-Classic is the format implemented today; OCA-PQC and
# future variants slot in under lib/ without a build-system fork.
#
# Targets:
#   all        — default; builds the test CLI (depends on lib + test).
#   lib        — builds the host static archive build/lib/liboca_validator.a.
#                Library translation units are compiled freestanding to prove
#                target portability; the archive itself is for the host test
#                CLI and CI, not a release artifact.
#   test       — builds the host test CLI build/test/oca-validate.
#   unit_test  — builds and runs the in-tree C unit-test driver.
#   check      — runs unit_test plus a fixture sweep that packs each
#                test/fixtures/configs/*.yaml via the project's Python packer
#                and validates the resulting binary against its .flags file.
#   clean      — removes build/.

CC          ?= cc
PROJECT_ROOT := $(abspath $(CURDIR)/../..)

# Resolve a Python interpreter that can import tt_boot_manifest.
#
# Search order:
#   1. $PYTHON if the user set it on the command line.
#   2. A repo-local venv at .venv/ or venv/.
#   3. The activated venv ($VIRTUAL_ENV/bin/python).
#   4. Plain `python` / `python3` on PATH.
#
# If none of those can import the packer, `make check` exits with a clear
# error pointing the operator at the venv path the project documents.
define _find_python
$(strip $(or                                                                  \
    $(and $(PYTHON),$(PYTHON)),                                               \
    $(wildcard $(PROJECT_ROOT)/.venv/bin/python),                             \
    $(wildcard $(PROJECT_ROOT)/venv/bin/python),                              \
    $(and $(VIRTUAL_ENV),$(VIRTUAL_ENV)/bin/python),                          \
    python,                                                                   \
    python3))
endef
PYTHON      := $(_find_python)

# -Wdocumentation and its unknown-command sibling are Clang-only. Probe the
# active compiler once and add them only if it accepts them, so a GCC build is
# unaffected. These check Doxygen markup against the declaration it sits on: a
# @param naming no such argument, a @return on a void function, a mistyped
# @parm. Cheap, and it runs on every build rather than only under pytest.
DOC_WARNINGS := $(shell $(CC) -Wdocumentation -Werror -x c -fsyntax-only /dev/null \
                  >/dev/null 2>&1 \
                  && echo "-Wdocumentation -Wdocumentation-unknown-command")

CFLAGS       := -std=c99 -Wall -Wextra -Werror -pedantic $(DOC_WARNINGS)

# Single hook for compile-time feature gates — variant restrictions today
# (e.g. -DOCA_SUPPORT_PQC=0), and whatever algorithm/feature toggles get added
# later. Folded into both the library and the CLI compiles. Empty by default
# (every variant/feature enabled). Pass your own on the command line:
#   make EXTRA_CFLAGS="-DOCA_SUPPORT_PQC=0 -DOCA_SUPPORT_SOME_ALGO=0"
# The variant-gated targets below append their gate to this rather than
# replacing it, so caller-supplied gates always survive.
EXTRA_CFLAGS ?=

# -MMD -MP: emit per-object header-dependency files (.d) so a header edit
# rebuilds every object that includes it (prevents stale-object ABI mismatches).
DEPFLAGS     := -MMD -MP

LIB_CFLAGS   := $(CFLAGS) -ffreestanding -nostdlib -fno-builtin -Os \
                -Ilib $(EXTRA_CFLAGS) $(DEPFLAGS)

# OpenSSL discovery via pkg-config (macOS Homebrew, Linux distros). The CLI
# tests need it for SHA-256 + signature verification. Override OPENSSL_CFLAGS
# / OPENSSL_LIBS on the make command line if your environment ships OpenSSL
# without a pkg-config file.
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   ?= $(shell pkg-config --libs openssl 2>/dev/null || echo "-lcrypto")

TEST_CFLAGS  := $(CFLAGS) -Ilib -Itest $(OPENSSL_CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS)
TEST_LIBS    := $(OPENSSL_LIBS)

BUILD        := build
LIB_BUILD    := $(BUILD)/lib
TEST_BUILD   := $(BUILD)/test
FIXTURE_BUILD := $(BUILD)/fixtures

# Flag-change detection.
#
# make decides what to rebuild from file timestamps, never from the command line
# it last used. So changing EXTRA_CFLAGS — the documented hook for
# -DOCA_TOC_MAX_IMAGES, -DOCA_SUPPORT_PQC=0 and the rest — silently reuses
# objects compiled with the PREVIOUS value, yielding a binary that does not match
# the flags you asked for. That has produced wrong test verdicts.
#
# Record the flags in a stamp file and make every object depend on it. The stamp
# is rewritten ONLY when the flags actually differ, so an unchanged build stays
# fully incremental.
LIB_STAMP    := $(LIB_BUILD)/.cflags
TEST_STAMP   := $(TEST_BUILD)/.cflags

LIB_SRCS     := $(wildcard lib/*.c)
LIB_OBJS     := $(patsubst lib/%.c,$(LIB_BUILD)/%.o,$(LIB_SRCS))
LIB_ARCHIVE  := $(LIB_BUILD)/liboca_validator.a

TEST_SRCS    := $(wildcard test/*.c)
TEST_MAIN    := test/main.c
UNIT_TEST_SRC := test/unit_test.c

TEST_CLI_OBJS := $(patsubst test/%.c,$(TEST_BUILD)/%.o, \
                  $(filter-out $(UNIT_TEST_SRC),$(TEST_SRCS)))
TEST_CLI      := $(TEST_BUILD)/oca-validate
UNIT_TEST_BIN := $(TEST_BUILD)/unit_test

.PHONY: all lib test unit_test check clean

all: $(TEST_CLI)

lib: $(LIB_ARCHIVE)

test: $(TEST_CLI)

unit_test: $(UNIT_TEST_BIN)
	@echo "running unit tests..."
	@$(UNIT_TEST_BIN)

check: unit_test fixture_sweep
	@echo "check: complete"

# Variant-gated builds.
#
# A single library normally handles every variant — the manifest magic selects
# one at runtime. A consumer that must NEVER accept a given variant (e.g., a
# pre-PQC ROM) can compile it out with the OCA_SUPPORT_* gates; the resolver
# then reports UNSUPPORTED_VARIANT for the excluded magic. These targets build
# the CLI three ways into isolated build dirs so the gate can be exercised:
#   both         — every variant (identical to the default `all`).
#   classic-only — PQC compiled out (-DOCA_SUPPORT_PQC=0).
#   pqc-only     — Classic compiled out (-DOCA_SUPPORT_CLASSIC=0).
.PHONY: both classic-only pqc-only

both:
	$(MAKE) BUILD=build/both all

classic-only:
	$(MAKE) BUILD=build/classic-only EXTRA_CFLAGS="$(EXTRA_CFLAGS) -DOCA_SUPPORT_PQC=0" all

pqc-only:
	$(MAKE) BUILD=build/pqc-only EXTRA_CFLAGS="$(EXTRA_CFLAGS) -DOCA_SUPPORT_CLASSIC=0" all

# Phase-1 stub: the per-target rules below are filled in by later phases.
# The skeleton commits to the strict-warnings posture so that the moment
# a real .c file shows up under lib/ or test/ it inherits the right flags.

# Always evaluated, but only writes when the flags differ — so it does not
# invalidate objects on every invocation.
.PHONY: FORCE
FORCE:

$(LIB_STAMP): FORCE | $(LIB_BUILD)
	@printf '%s' '$(LIB_CFLAGS)' | cmp -s - $@ 2>/dev/null \
		|| { printf '%s' '$(LIB_CFLAGS)' > $@; \
		     echo "flags changed -> rebuilding lib objects"; }

$(TEST_STAMP): FORCE | $(TEST_BUILD)
	@printf '%s' '$(TEST_CFLAGS)' | cmp -s - $@ 2>/dev/null \
		|| { printf '%s' '$(TEST_CFLAGS)' > $@; \
		     echo "flags changed -> rebuilding test objects"; }

$(LIB_BUILD)/%.o: lib/%.c $(LIB_STAMP) | $(LIB_BUILD)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(TEST_BUILD)/%.o: test/%.c $(TEST_STAMP) | $(TEST_BUILD)
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# Pull in auto-generated header dependencies (.d) emitted by -MMD, so editing a
# header rebuilds every dependent object. Never fail if none exist yet.
-include $(wildcard $(LIB_BUILD)/*.d $(TEST_BUILD)/*.d)

$(LIB_ARCHIVE): $(LIB_OBJS) | $(LIB_BUILD)
	@if [ -z "$(LIB_OBJS)" ]; then \
		echo "lib: no library sources yet — skipping archive"; \
	else \
		ar rcs $@ $(LIB_OBJS); \
		echo "lib: built $@"; \
	fi

$(TEST_CLI): $(LIB_ARCHIVE) $(TEST_CLI_OBJS) | $(TEST_BUILD)
	@if [ -z "$(TEST_CLI_OBJS)" ]; then \
		echo "test: no CLI sources yet — skipping link"; \
	else \
		$(CC) $(TEST_CFLAGS) $(TEST_CLI_OBJS) $(LIB_ARCHIVE) $(TEST_LIBS) -o $@; \
		echo "test: built $@"; \
	fi

$(UNIT_TEST_BIN): $(LIB_ARCHIVE) $(TEST_BUILD)/unit_test.o | $(TEST_BUILD)
	@if [ ! -e test/unit_test.c ]; then \
		echo "unit_test: no test/unit_test.c yet — skipping link"; \
	else \
		$(CC) $(TEST_CFLAGS) $(TEST_BUILD)/unit_test.o $(LIB_ARCHIVE) -o $@; \
		echo "unit_test: built $@"; \
	fi

fixture_sweep: $(TEST_CLI) | $(FIXTURE_BUILD)
	@$(PYTHON) -c "import tt_boot_manifest" 2>/dev/null \
		|| { echo "fixture_sweep: $(PYTHON) cannot import tt_boot_manifest."; \
		     echo "  Either activate the project virtualenv:"; \
		     echo "    source <venv>/bin/activate"; \
		     echo "  or point make at it directly:"; \
		     echo "    make PYTHON=<venv>/bin/python check"; \
		     exit 1; }
	@found=0; pass=0; fail=0; \
	for cfg in test/fixtures/configs/*.yaml; do \
		[ -e "$$cfg" ] || continue; \
		found=$$((found+1)); \
		name=$$(basename "$$cfg" .yaml); \
		bin="$(FIXTURE_BUILD)/$$name.bin"; \
		flags="test/fixtures/configs/$$name.flags"; \
		pack_err=$$( cd $(PROJECT_ROOT) && $(PYTHON) -m tt_boot_manifest.pack_images \
			--config validators/oca/$$cfg --out validators/oca/$$bin 2>&1 >/dev/null ); \
		if [ -n "$$pack_err" ] && [ ! -s "$$bin" ]; then \
			echo "fixture: pack $$name FAILED: $$pack_err"; \
			fail=$$((fail+1)); continue; \
		fi; \
		extra=""; [ -e "$$flags" ] && extra=$$(cat "$$flags"); \
		if $(TEST_CLI) --manifest "$$bin" $$extra >/dev/null 2>&1; then \
			echo "PASS: $$name"; pass=$$((pass+1)); \
		else \
			err=$$($(TEST_CLI) --manifest "$$bin" $$extra 2>&1 >/dev/null); \
			echo "FAIL: $$name: $$err"; fail=$$((fail+1)); \
		fi; \
	done; \
	if [ $$found -eq 0 ]; then echo "fixture_sweep: no fixtures yet"; \
	else echo "$$pass/$$found passed"; [ $$fail -eq 0 ]; fi

$(LIB_BUILD) $(TEST_BUILD) $(FIXTURE_BUILD):
	@mkdir -p $@

clean:
	rm -rf $(BUILD)

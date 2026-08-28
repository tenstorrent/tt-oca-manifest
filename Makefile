# Documentation build for the OCA boot manifest specification.
#
# Renders the AsciiDoc specification to PDF with asciidoctor-pdf. This is the
# only thing this top-level Makefile builds; the C validator has its own build
# system under validators/oca/Makefile.
#
# The toolchain knobs, theme, and asciidoctor-pdf invocation mirror the OCA
# harness documentation build (doc/doc.mk and doc/theme.yml there), so a spec
# PDF built here matches the consumer-side documentation set.
#
# Targets:
#   spec-pdf (default) — render the specification to $(SPEC_PDF)
#   clean              — remove the build directory
#   help               — list the targets
#
# Requires asciidoctor-pdf on PATH: `gem install asciidoctor-pdf`
# (macOS: `brew install asciidoctor && gem install asciidoctor-pdf`).

ASCIIDOCTOR_PDF ?= asciidoctor-pdf
BUILD_DIR       ?= build

SPEC_DIR       := $(abspath specifications)
SPEC_SRC       := $(SPEC_DIR)/oca/boot-manifest.adoc
SPEC_IMAGES    := $(wildcard $(SPEC_DIR)/oca/images/*)
PDF_THEME      ?= $(SPEC_DIR)/theme.yml
PDF_THEMESDIR  ?= $(SPEC_DIR)
SPEC_PDF       := $(BUILD_DIR)/oca-boot-manifest.pdf

# -d book               — with the heading promotion below this makes the spec's
#                         own top-level heading the document title, which yields
#                         a title page, a contents page, and a page break per
#                         top-level section.
# -a leveloffset=-2     — the specification source is written to be included in
#                         the larger OCA system architecture spec, so its
#                         headings start at level 3 (`=== Payload Manifest`).
#                         Promoting by two levels makes that the document title
#                         and its subsections top-level; without it the PDF is
#                         an untitled document of deeply nested sections.
# --failure-level=ERROR — asciidoctor-pdf reports content loss as an ERROR but
#                         still exits 0. The one that bites here: it cannot
#                         split a table cell across pages, so a Description cell
#                         that outgrows a page is silently truncated. This turns
#                         that into a build failure instead of a hole in the
#                         published spec. See specifications/theme.yml.
ASCIIDOCTOR_FLAGS ?= -d book \
                     -a leveloffset=-2 \
                     -a toc \
                     -a toclevels=3 \
                     -a sectnums \
                     -a pdf-theme=$(PDF_THEME) \
                     -a pdf-themesdir=$(PDF_THEMESDIR) \
                     --failure-level=ERROR

.PHONY: all spec-pdf clean help
.DEFAULT_GOAL := spec-pdf

all: spec-pdf

## Render the OCA boot manifest specification to PDF.
spec-pdf: $(SPEC_PDF)

$(SPEC_PDF): $(SPEC_SRC) $(PDF_THEME) $(SPEC_IMAGES)
	@command -v $(ASCIIDOCTOR_PDF) >/dev/null 2>&1 || { \
	    echo "error: asciidoctor-pdf not found ($(ASCIIDOCTOR_PDF))."; \
	    echo "install it with:"; \
	    echo "  gem install asciidoctor-pdf"; \
	    echo "or point this build at an existing install:"; \
	    echo "  make spec-pdf ASCIIDOCTOR_PDF=/path/to/asciidoctor-pdf"; \
	    exit 1; }
	@echo "Building specification PDF (asciidoctor-pdf)"
	@mkdir -p $(@D)
	@$(ASCIIDOCTOR_PDF) $(ASCIIDOCTOR_FLAGS) -o $@ $(SPEC_SRC)
	@echo "Done: $@"

## Remove the documentation build artifacts.
clean:
	@rm -rf $(BUILD_DIR)
	@echo "Cleaned $(BUILD_DIR)/"

## List the available targets.
help:
	@echo "Targets:"
	@echo "  spec-pdf  Render the OCA boot manifest specification to $(SPEC_PDF) (default)"
	@echo "  clean     Remove $(BUILD_DIR)/"
	@echo "  help      Show this message"
	@echo ""
	@echo "Variables:"
	@echo "  ASCIIDOCTOR_PDF   asciidoctor-pdf executable (default: asciidoctor-pdf)"
	@echo "  BUILD_DIR         output directory (default: build)"
	@echo "  PDF_THEME         theme file (default: specifications/theme.yml)"
	@echo "  ASCIIDOCTOR_FLAGS flags passed to asciidoctor-pdf"

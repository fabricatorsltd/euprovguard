# EUProvGuard Makefile
# @standard Cyber Resilience Act (EU) 2024/2353 - SLSA Level 3 build requirements
# @standard ETSI EN 303 645 - secure build pipeline

BINARY     = euprovguard
VERSION    = 1.2.0
MODULE     = euprovguard
GO         = go
GOFLAGS    = CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH)
LDFLAGS    = -ldflags="-s -w -X main.Version=$(VERSION)"
GOOS      ?= linux
GOARCH    ?= amd64

# Build targets
DIST_DIR   = dist

.PHONY: all build test lint clean sbom verify install help

all: build

## build: Compile static binary (CGO_ENABLED=0)
build:
	@echo "[BUILD] Compiling $(BINARY) v$(VERSION) ($(GOOS)/$(GOARCH))..."
	@mkdir -p $(DIST_DIR)
	$(GOFLAGS) $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY) ./
	@echo "[BUILD] Binary: $(DIST_DIR)/$(BINARY)"

## build-all: Cross-compile for Linux, Windows, macOS
build-all:
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			echo "[BUILD] $$os/$$arch..."; \
			ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(LDFLAGS) \
				-o $(DIST_DIR)/$(BINARY)-$$os-$$arch$$ext ./; \
		done; \
	done

## test: Run unit tests
test:
	@echo "[TEST] Running tests..."
	$(GO) test -v -count=1 ./test/... ./pkg/...

## test-race: Run tests with race detector
test-race:
	@echo "[TEST] Running tests with race detector..."
	$(GO) test -race -v ./test/... ./pkg/...

## lint: Run static analysis
lint:
	@echo "[LINT] Running go vet..."
	$(GO) vet ./...

## sbom: Generate SBOM for this project (self-attestation, CRA Article 13)
sbom: build
	@echo "[SBOM] Generating self-SBOM (CRA Article 13 compliance)..."
	$(DIST_DIR)/$(BINARY) -path . -output sbom-$(BINARY)-$(VERSION).json
	@echo "[SBOM] Written: sbom-$(BINARY)-$(VERSION).json"

## verify: Verify existing SBOM signature
verify:
	@echo "[VERIFY] Verifying SBOM signature..."
	$(DIST_DIR)/$(BINARY) -verify -input sbom-$(BINARY)-$(VERSION).json

## clean: Remove build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts..."
	rm -rf $(DIST_DIR)
	rm -f sbom-*.json report-*.html report-*.txt *.signed

## install: Install binary to /usr/local/bin
install: build
	@echo "[INSTALL] Installing $(BINARY) to /usr/local/bin..."
	install -m 755 $(DIST_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

## help: Show this help
help:
	@echo "EUProvGuard v$(VERSION) - CRA/eIDAS SBOM Generator"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /'

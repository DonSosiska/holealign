GO ?= go
export CGO_ENABLED=0

.PHONY: build test vet lint vulncheck tidy release-snapshot docker rules-bundle

build:
	$(GO) build -trimpath -o bin/ ./cmd/...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipped"

# Binary-mode govulncheck against .govulncheck-allow (see docs/development.md).
vulncheck:
	bash scripts/govulncheck.sh

# Pack the shipped rules and their tests into dist/rules/rules-$(RULES_SEQ).tar.gz (reproducible: created_at
# comes from the last commit). With RULES_KEY=<private key file> the bundle is also signed (.sig + latest.json).
RULES_SEQ ?= 1
rules-bundle:
	SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) $(GO) run ./cmd/panoptes-server rules build \
		-rules rules -tests rules-tests -seq $(RULES_SEQ) -out dist/rules
	@if [ -n "$(RULES_KEY)" ]; then $(GO) run ./cmd/panoptes-server rules sign -key "$(RULES_KEY)" dist/rules/rules-$(RULES_SEQ).tar.gz; fi

tidy:
	$(GO) mod tidy

# Local goreleaser dry run: archives, .deb/.rpm, checksums. Nothing is published.
release-snapshot:
	goreleaser release --snapshot --clean

# Server image built from source (no goreleaser needed).
docker:
	docker build -f deploy/Dockerfile.server.build \
		--build-arg VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
		-t panoptes-server:dev .

GO ?= go
export CGO_ENABLED=0

.PHONY: build test vet lint tidy release-snapshot docker

build:
	$(GO) build -trimpath -o bin/ ./cmd/...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipped"

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

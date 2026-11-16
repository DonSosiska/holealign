GO ?= go
export CGO_ENABLED=0

.PHONY: build test vet lint tidy

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

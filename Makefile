# Makefile for Augustus - LLM Vulnerability Scanner

.PHONY: all build build-whisper test test-cover lint clean install help multimodal-assets-verify generate generate-check
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

# Configurable variables (environment override with ?=)
GO ?= go
BINARY ?= augustus
BUILD_DIR ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
GOLANGCI_LINT_VERSION ?= v2.12.2

# Auto-discover source files
GO_SOURCES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

help: ## Display available targets
	@grep -E '^[a-zA-Z_/-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

all: build ## Build the project (default)

build: $(BUILD_DIR)/$(BINARY) ## Build augustus binary

$(BUILD_DIR)/$(BINARY): $(GO_SOURCES) | $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $@ ./cmd/augustus

$(BUILD_DIR):
	mkdir -p $@

test: ## Run all tests
	$(GO) test -v -race ./...

test-cover: ## Run tests with coverage report
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-equiv: ## Run equivalence tests
	$(GO) test -v ./tests/equivalence/...

lint: ## Run linter (requires golangci-lint)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) 2>/dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not available, running go vet..."; \
		go vet ./...; \
	fi

multimodal-assets-verify: ## Verify multimodal probe assets carry their canaries
	cd tools/multimodal-assets && python3 verify.py --check-committed --repo-root ../..

generate: ## Regenerate pkg/register blank-import files from internal/<type>/
	$(GO) generate ./...

generate-check: generate ## Fail if generated register files are out of date
	@git diff --exit-code -- pkg/register || { \
		echo "pkg/register is out of date; run 'make generate' and commit the result." >&2; \
		exit 1; \
	}

build-whisper: ## Build with whisper.cpp audio transcription (requires libwhisper + CGO)
	CGO_ENABLED=1 $(GO) build -tags whisper -o $(BUILD_DIR)/$(BINARY) ./cmd/augustus

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR) coverage.out coverage.html

install: build ## Install binary to $GOPATH/bin
	$(GO) install ./cmd/augustus

# Makefile for Augustus - LLM Vulnerability Scanner

.PHONY: all build test test-cover lint clean install help
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

# Configurable variables (environment override with ?=)
GO ?= go
BINARY ?= augustus
BUILD_DIR ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

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
	golangci-lint run ./...

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR) coverage.out coverage.html

install: build ## Install binary to $GOPATH/bin
	$(GO) install ./cmd/augustus

---
title: Installation & Build
tags: [augustus, overview, build]
type: overview
status: complete
---

# Installation & Build

## Prerequisites

- **Go 1.27.0 or later** (the version pinned in `go.mod`).
- `make` for the convenience targets (optional — you can build directly with `go`).
- `golangci-lint v2.13.1` for linting (the `lint` target runs this exact version via `go run`).

## Install via `go install`

```bash
go install github.com/praetorian-inc/augustus/cmd/augustus@latest
```

This drops the `augustus` binary into `$GOPATH/bin`.

## Build From Source

```bash
git clone https://github.com/praetorian-inc/augustus.git
cd augustus
make build            # builds to bin/augustus
```

`make build` compiles `./cmd/augustus` with version info stamped via ldflags (`-X main.version=...`, derived from `git describe`). To build without make:

```bash
go build ./cmd/augustus
```

## Make Targets

| Target | What it does |
|--------|--------------|
| `make build` | Build the binary to `bin/augustus` (default goal is `help`). |
| `make all` | Alias for `build`. |
| `make test` | Run all tests with the race detector (`go test -v -race ./...`). |
| `make test-cover` | Run tests with coverage, emit `coverage.html`. |
| `make test-equiv` | Run Go-vs-Python equivalence tests (`./tests/equivalence/...`). |
| `make lint` | Run the pinned `golangci-lint v2.13.1` via `go run`. |
| `make install` | `go install ./cmd/augustus` into `$GOPATH/bin`. |
| `make clean` | Remove `bin/`, `coverage.out`, `coverage.html`. |
| `make help` | List available targets (default goal). |

## Running Tests

```bash
make test                      # all packages, race detection
go test ./pkg/scanner -v       # one package
go test ./... -run TestName    # a single test by name
make test-cover                # coverage report → coverage.html
```

## Linting & Formatting

CI enforces formatting via the shared Go CI workflow, so keep the tree clean:

```bash
make lint                      # golangci-lint per .golangci.yml
golangci-lint fmt ./...        # apply gofumpt + goimports (what CI checks)
```

Plain `go fmt` is **not** sufficient — the lint gate requires `gofumpt` + `goimports` formatting.

## Next

- [[Quickstart]] — run your first scan.
- [[What Is Augustus]] · [[Home]]

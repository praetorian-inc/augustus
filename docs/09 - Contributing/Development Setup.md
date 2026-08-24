---
title: Development Setup
tags: [augustus, contributing, setup]
type: guide
status: complete
---

# Development Setup

> Get a working Augustus checkout: clone, install the Go toolchain, build the binary, run a scan, and wire up your editor for the lint/format gate that CI enforces.

## Prerequisites

- **Go** — the module targets the version pinned in `go.mod` (`go 1.25.3`). Use that or newer.
- **Git** — version control.
- **Make** — build automation (the `Makefile` wraps the common targets).
- **golangci-lint v2** (`v2.13.1`, pinned in the `Makefile`) — for the format/lint gate. `make lint` auto-installs the pinned version if it is missing and falls back to `go vet`.

## Clone

```bash
git clone https://github.com/praetorian-inc/augustus.git
cd augustus
# if working from a fork, add upstream:
git remote add upstream https://github.com/praetorian-inc/augustus.git
```

## Build

```bash
make build                 # builds bin/augustus (with version ldflags)
go build ./cmd/augustus    # alternative direct build
```

The CLI is Kong-based and lives in `cmd/augustus/` (`main.go`, `cli.go`, `scan.go`).

## Run

```bash
# basic scan: generator, probe, detector
bin/augustus scan openai.OpenAI --probe dan.Dan_11_0 --detector dan.DAN

# batch via glob
bin/augustus scan anthropic.Anthropic --probes-glob "dan.*,goodside.*"

# custom REST endpoint
bin/augustus scan rest.Rest --probe dan.Dan_11_0 --config '{"uri":"https://api.example.com/v1/chat"}'
```

Provider credentials are supplied via `--config '{"api_key":"..."}'` or environment variables (see [[Adding a Generator]] for the env-var fallback convention).

## Test

```bash
make test                  # go test -v -race ./...
go test ./pkg/scanner -v   # one package
go test ./... -run TestName # one test by name
make test-cover            # coverage -> coverage.html
```

See [[Testing & Equivalence Tests]] for layout and the `test-equiv` target.

## Editor / lint setup

CI enforces a `golangci-lint fmt`-clean tree via `gofumpt` + `goimports` (config in `.golangci.yml`). Plain `go fmt` is **not** sufficient. Format and lint locally before committing:

```bash
golangci-lint fmt ./...    # apply gofumpt + goimports (matches CI)
make lint                  # run the standard linter set
```

For your IDE, point the Go formatter at `gofumpt` and enable `goimports` with local-prefix `github.com/praetorian-inc/augustus` so import grouping matches `.golangci.yml`. Details in [[Linting, CI & Commits]].

## Project layout

```
cmd/augustus/       CLI (Kong) - main.go, cli.go, scan.go
pkg/                Public interfaces + shared utilities
  types/            Canonical Prober/Generator/Detector interfaces
  registry/         Generic factory registration + config helpers
  scanner/          Concurrent execution (errgroup)
  templates/        YAML probe loader (embed.FS)
internal/           Implementation details (not importable externally)
  probes/           230+ probes by category
  generators/       28 provider integrations
  detectors/        95+ detectors
  buffs/            7 buff transformations
```

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Core Interfaces]]
- [[Installation & Build]]

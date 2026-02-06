# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Augustus is a Go-based LLM vulnerability scanner that tests large language models against 210+ adversarial attacks. It integrates with 28 LLM providers and produces actionable vulnerability reports.

## Build and Test Commands

```bash
# Build
make build                    # Build binary to bin/augustus
go build ./cmd/augustus       # Alternative direct build

# Test
make test                     # Run all tests with race detection
go test ./pkg/scanner -v      # Run specific package tests
go test ./... -run TestName   # Run single test by name
make test-equiv               # Run equivalence tests (Go vs Python)
make test-cover               # Run tests with coverage report

# Lint
make lint                     # Run golangci-lint (requires installation)
go fmt ./...                  # Format code
```

## Architecture

### Core Interfaces (pkg/types/)

All capabilities implement these interfaces:
- **Prober**: Generates attack prompts, returns `[]*attempt.Attempt`
- **Generator**: Wraps LLM APIs, handles `*attempt.Conversation` → `[]attempt.Message`
- **Detector**: Analyzes outputs, returns scores `[0.0, 1.0]` (0=safe, 1=vulnerable)
- **Buff**: Transforms prompts before sending (encoding, translation, paraphrase)

### Plugin Registration Pattern

Capabilities self-register via `init()` functions. Example:

```go
// internal/probes/dan/templates.go
func init() {
    probes.Register("dan.Dan", func(_ registry.Config) (probes.Prober, error) {
        return &DanProbe{}, nil
    })
}
```

Global registries in `pkg/` packages:
- `probes.Registry`, `detectors.Registry`, `generators.Registry`, `buffs.Registry`

### Directory Structure

```
cmd/augustus/       CLI (Kong-based) - main.go, cli.go, scan.go
pkg/                Public interfaces and shared utilities
  types/            Canonical interface definitions (Prober, Generator, Detector)
  registry/         Generic factory registration with typed configs
  scanner/          Concurrent execution with errgroup
  buffs/            Buff interface and chaining
  attempt/          Attempt/Conversation/Message types
  templates/        YAML probe template loader (Nuclei-style)
internal/           Implementation details (not importable externally)
  probes/           210+ probe implementations organized by category
  generators/       28 provider integrations (43 variants)
  detectors/        90+ detector implementations
  buffs/            7 buff transformations
  attackengine/     Iterative attack engine (PAIR/TAP)
```

### Scan Pipeline

1. **Probe Selection** → 2. **Buff Transform** → 3. **Generator Call** → 4. **Detector Analysis** → 5. **Result Recording**

Scanner uses `errgroup` for bounded concurrency (default 10 goroutines).

## Adding New Components

### New Probe

1. Create `internal/probes/<category>/<name>.go`
2. Implement `types.Prober` interface
3. Register in `init()`: `probes.Register("category.Name", factory)`
4. Add tests in `*_test.go`

For YAML-based probes, create `.yaml` files in `data/` subdirectory and use `templates.NewLoader()`.

### New Generator

1. Create `internal/generators/<provider>/`
2. Implement `types.Generator` interface
3. Register: `generators.Register("provider.Name", factory)`
4. Handle configuration via `registry.Config` map

### New Detector

1. Create `internal/detectors/<category>/`
2. Implement `types.Detector` interface (return scores 0.0-1.0)
3. Register: `detectors.Register("category.Name", factory)`

## Key Patterns

- **Typed Configuration**: Use `registry.FromMap()` to adapt typed configs to `registry.Config` maps
- **YAML Templates**: Probe prompts can be defined in YAML using `embed.FS` and `templates.Loader`
- **Aho-Corasick**: Fast keyword matching for detectors via `internal/ahocorasick/`
- **Rate Limiting**: Token bucket in `pkg/ratelimit/`
- **Retry Logic**: Exponential backoff with jitter in `pkg/retry/`

## CLI Usage Patterns

```bash
# Basic scan
augustus scan openai.OpenAI --probe dan.Dan --detector dan.DanDetector

# Glob patterns for batch runs
augustus scan anthropic.Anthropic --probes-glob "encoding.*,dan.*" --all-detectors

# Apply buff transformations
augustus scan openai.OpenAI --all --buff encoding.Base64

# Custom REST endpoint
augustus scan rest.Rest --probe dan.Dan --config '{"uri":"https://api.example.com/v1/chat"}'
```

## Commit Convention

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`

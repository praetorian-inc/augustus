# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Augustus is a Go-based LLM vulnerability scanner that tests large language models against 230+ adversarial attacks. It integrates with 28 LLM providers and produces actionable vulnerability reports.

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

# Lint & format
make lint                     # Run golangci-lint per .golangci.yml (standard linters + gofumpt/goimports formatters); auto-installs the pinned version, falls back to go vet if unavailable
golangci-lint fmt ./...       # Apply gofumpt + goimports formatting — matches what CI enforces (plain `go fmt` no longer satisfies the lint gate)
```

Linting is configured by `.golangci.yml` (golangci-lint v2): the default `standard` linter set plus a `formatters` block enabling `gofumpt` and `goimports`. CI runs this via the shared `public-workflows/go-ci.yml` reusable workflow on every PR, so formatting drift fails the build — keep the tree `golangci-lint fmt`-clean.

## Architecture

### Core Interfaces (pkg/types/)

All capabilities implement these interfaces:
- **Prober**: Generates attack prompts, returns `[]*attempt.Attempt`
- **Generator**: Wraps LLM APIs, handles `*attempt.Conversation` → `[]attempt.Message`
- **Detector**: Analyzes outputs, returns scores `[0.0, 1.0]` (0=safe, 1=vulnerable)
- **Buff**: Transforms prompts before sending (encoding, translation, paraphrase)

Probes may also implement these **optional** interfaces (all in `pkg/types/prober.go`) for advanced behavior:
- **ProbeMetadata**: `Description`/`Goal`/`GetPrimaryDetector`/`GetPrompts` for introspection
- **ProbeDetectorConfig**: `GetDetectorConfig()` — per-probe detector config overrides
- **ProbeSecondaryDetectors**: `GetSecondaryDetectors()` — run extra detectors alongside the primary; the attempt verdict reflects the **max score across all detectors** (see `attempt.GetEffectiveScores`), so a secondary hit alone marks the attempt vulnerable
- **ProbeTools**: `GetTools()` / `GetToolChoice()` — declare function-calling tool schemas for tool-use/agent probes (sent via the native wire layer in `internal/attackengine/toolcalls.go`)

Generators may also implement these **optional** interfaces (in `pkg/types/generator.go`):
- **UsageReporter**: `AccumulatedTokens() int64` — reports the cumulative tokens consumed across all `Generate` calls. The scanner type-asserts each generator for this interface and records the per-run delta into `Metrics.TokensConsumed` (surfaced as `augustus_tokens_consumed`). Implement it for free by embedding `types.UsageCounter` (a concurrency-safe `atomic.Int64`) and calling `g.AddTokens(...)` wherever the provider returns usage. Generators whose provider doesn't report usage still embed `UsageCounter` and simply never `AddTokens`, contributing 0 (honest partial coverage, never an estimate).
- **VisionCapable**: `SupportsVision() bool` — declares that the generator's wire layer can transmit image attachments (`Message.Images`). Multimodal image probes gate on this to skip generators that can't carry images rather than silently sending a text-only request and mis-reporting the target as safe. Report **structural** capability (the generator emits image content blocks), not per-model support — e.g. an OpenAI-compatible generator returns `true` on its chat path even though a given model may ignore images; for generators with both image-capable and text-only paths (OpenAI/Azure completion models, Bedrock Titan/Llama), return the path-accurate value (e.g. `g.isChat`, or the model family).
- **DocumentCapable**: `SupportsDocuments() bool` — the document-modality parallel of `VisionCapable`: declares that the generator's wire layer can transmit document attachments (`Message.Documents`, e.g. PDFs). Document probes (`internal/probes/pdf/*`) gate on this so a generator that can't carry documents fails the probe rather than silently sending a text-only request and mis-reporting the target as safe. Report **structural** capability — Anthropic returns `true` unconditionally; Bedrock returns `true` only for the Claude builder (Nova/Titan/Llama return `false`, as only the Claude path emits document blocks).
- **ToolInvoker** (`pkg/types/tool_invoker.go`): `ListTools()` / `CallTool()` — declares that the target exposes a directly-invokable tool surface (e.g. an MCP server) rather than only chat completion. This is distinct from the model-facing tool wire layer (`Conversation.Tools`/`Message.ToolCalls`), which presents probe-defined tools *to* an LLM and executes nothing: `ToolInvoker` invokes REAL tools on the backend. It is the basis for the `internal/probes/toolsec/*` probes (authorization, injection-into-a-sink, SSRF against tool backends).
- **MCPReconnaissance** (`pkg/types/mcp_recon.go`): `MCPInventory()` — declares that the target's full MCP attack surface (declared capabilities, negotiated protocol version, server instructions, and the tool/resource/prompt catalog) can be enumerated from the connected session. Implemented by the `mcp.MCP` generator and consumed by the `recon.MCP` reconnaissance module. Assembles raw descriptive data only — it renders no verdict.

### Reconnaissance (pkg/recon/)

Reconnaissance is a **first-class activity distinct from probing**: it *measures* (gathers descriptive facts) and renders no verdict, whereas probes produce scored attempts. The distinction is enforced by the type system — a reconnaissance module returns `[]output.Observation`, never a score.

- **Recon** (`pkg/recon/recon.go`): `Recon(ctx, gen) ([]output.Observation, error)` + `Name()` — a reconnaissance module (e.g. `recon.MCP` in `internal/recon/mcp/`). It gates on the target's capability (type-asserting an optional interface such as `MCPReconnaissance`) and returns no observations for inapplicable targets. Results flow into a shared, concurrency-safe `recon.Store`.
- **Observation** (`pkg/output/output.go`): the one descriptive output type (`Type`/`Target`/`Data`/`Source`). The verdict stays the probe score; it is never re-represented as an observation.
- **ContextAwareProbe** (opt-in, `pkg/recon/context.go`): `SetContext(ProbeContext)` — a probe that consumes prior reconnaissance (the "scan once, reuse everywhere" model). The runner delivers the shared `Store` before probing; probes that don't implement it structurally cannot see recon. `toolsec.Injection`/`SSRF` use it to reuse a prior MCP inventory instead of re-enumerating the tool surface.

### Plugin Registration Pattern

Capabilities self-register via `init()` functions. Example:

```go
// internal/probes/dan/templates.go
func init() {
    probes.Register("dan.Dan_11_0", func(_ registry.Config) (probes.Prober, error) {
        return &DanProbe{}, nil
    })
}
```

Global registries in `pkg/` packages:
- `probes.Registry`, `detectors.Registry`, `generators.Registry`, `buffs.Registry`, `recon.Registry`

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
  recon/            Recon interface, registry, and the shared observation Store
  output/           Observation type (descriptive, non-verdict output)
internal/           Implementation details (not importable externally)
  probes/           230+ probe implementations organized by category
  generators/       30 provider integrations (45 variants)
  detectors/        95+ detector implementations
  buffs/            7 buff transformations
  attackengine/     Iterative attack engine (PAIR/TAP)
  recon/            Reconnaissance modules (e.g. recon/mcp — MCP attack-surface enumeration)
```

### Scan Pipeline

0. **Reconnaissance** (optional, `--recon`) → 1. **Probe Selection** → 2. **Buff Transform** → 3. **Generator Call** → 4. **Detector Analysis** → 5. **Result Recording**

When `--recon` modules are given, a reconnaissance phase runs **before** probe selection, independent of the detector harness: it populates a shared `recon.Store` (observations emitted as JSONL) and feeds context-aware probes. A **recon-only scan** (recon modules but no probes) is valid and skips the probe/detector harness entirely.

Scanner uses `errgroup` for bounded concurrency (default 10 goroutines).

## Adding New Components

### New Probe

1. Create `internal/probes/<category>/<name>.go`
2. Implement `types.Prober` interface
3. Register in `init()`: `probes.Register("category.Name", factory)`
4. Add tests in `*_test.go`

For YAML-based probes, create `.yaml` files in `data/` subdirectory and use `templates.NewLoader()`. YAML templates support advanced fields consumed via the optional interfaces above: `detector_config`, `secondary_detectors`, and — for tool-use/function-calling probes — `tools`, `tool_choice`, `tool_results`, and `mode: [chat, native]`. The canonical `TemplateProbe` (`pkg/templates/probe.go`) implements all optional interfaces; see `internal/probes/tooluse/data/*.yaml` for tool-use attack examples (unauthorized invocation, parameter injection, selection hijacking, etc.).

### New Generator

1. Create `internal/generators/<provider>/`
2. Implement `types.Generator` interface
3. Register: `generators.Register("provider.Name", factory)`
4. Handle configuration via `registry.Config` map
5. Embed `types.UsageCounter` (satisfies the optional `UsageReporter`) and call `g.AddTokens(...)` at each usage-parse site so the provider's token counts flow into `Metrics.TokensConsumed`; leave it un-incremented if the provider returns no usage

### New Detector

1. Create `internal/detectors/<category>/`
2. Implement `types.Detector` interface (return scores 0.0-1.0)
3. Register: `detectors.Register("category.Name", factory)`

### New Reconnaissance Module

1. Create `internal/recon/<name>/`
2. Implement `recon.Recon` — return `[]output.Observation` (descriptive facts), never a score
3. Register: `recon.Register("recon.Name", factory)`
4. Gate on the target's capability (e.g. type-assert `types.MCPReconnaissance`) and return no observations for inapplicable targets — a module that can't operate is a skip, not an error

## Key Patterns

- **Typed Configuration**: Use `registry.FromMap()` to adapt typed configs to `registry.Config` maps
- **YAML Templates**: Probe prompts can be defined in YAML using `embed.FS` and `templates.Loader`
- **Aho-Corasick**: Fast keyword matching for detectors via `internal/ahocorasick/`
- **Rate Limiting**: Token bucket in `pkg/ratelimit/`
- **Retry Logic**: Exponential backoff with jitter in `pkg/retry/`

## CLI Usage Patterns

```bash
# Basic scan
augustus scan openai.OpenAI --probe dan.Dan_11_0 --detector dan.DAN

# Glob patterns for batch runs
augustus scan anthropic.Anthropic --probes-glob "dan.*,goodside.*"

# Apply buff transformations
augustus scan openai.OpenAI --all --buff encoding.Base64

# Custom REST endpoint
augustus scan rest.Rest --probe dan.Dan_11_0 --config '{"uri":"https://api.example.com/v1/chat"}'

# Reconnaissance (first-class; --recon is repeatable and may run with or without probes)
augustus scan mcp.MCP --recon recon.MCP --config '{"endpoint":"http://localhost:8000/mcp"}'

# Recon feeding tool-surface probes in one scan (scan once, reuse everywhere)
augustus scan mcp.MCP --recon recon.MCP --probe toolsec.Injection --probe toolsec.SSRF --config '{"endpoint":"http://localhost:8000/mcp"}'
```

## Commit Convention

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`

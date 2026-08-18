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
- **RiskDescriber**: `RiskInfo()` — carry a curated `types.RiskInfo` write-up (description/impact/recommendation/references/taxonomies/CVSS v4.0 vector/verification) next to the probe so consumers retrieve it via type assertion instead of duplicating it. `Verification` is a static, reproduction-oriented write-up (how the probe confirms the finding + how to reproduce it) distinct from `Description`; it carries no live target values and no template tokens, so a consumer can render it and safely append a data-built reproduction command

Generators may also implement these **optional** interfaces (in `pkg/types/generator.go`):
- **UsageReporter**: `AccumulatedTokens() int64` — reports the cumulative tokens consumed across all `Generate` calls. The scanner type-asserts each generator for this interface and records the per-run delta into `Metrics.TokensConsumed` (surfaced as `augustus_tokens_consumed`). Implement it for free by embedding `types.UsageCounter` (a concurrency-safe `atomic.Int64`) and calling `g.AddTokens(...)` wherever the provider returns usage. Generators whose provider doesn't report usage still embed `UsageCounter` and simply never `AddTokens`, contributing 0 (honest partial coverage, never an estimate).
- **VisionCapable**: `SupportsVision() bool` — declares that the generator's wire layer can transmit image attachments (`Message.Images`). Multimodal image probes gate on this to skip generators that can't carry images rather than silently sending a text-only request and mis-reporting the target as safe. Report **structural** capability (the generator emits image content blocks), not per-model support — e.g. an OpenAI-compatible generator returns `true` on its chat path even though a given model may ignore images; for generators with both image-capable and text-only paths (OpenAI/Azure completion models, Bedrock Titan/Llama), return the path-accurate value (e.g. `g.isChat`, or the model family).
- **DocumentCapable**: `SupportsDocuments() bool` — the document-modality parallel of `VisionCapable`: declares that the generator's wire layer can transmit document attachments (`Message.Documents`, e.g. PDFs). Document probes (`internal/probes/pdf/*`) gate on this so a generator that can't carry documents fails the probe rather than silently sending a text-only request and mis-reporting the target as safe. Report **structural** capability — Anthropic returns `true` unconditionally; Bedrock returns `true` only for the Claude builder (Nova/Titan/Llama return `false`, as only the Claude path emits document blocks).
- **ToolInvoker** (`pkg/types/tool_invoker.go`): `ListTools()` / `CallTool()` — declares that the target exposes a directly-invokable tool surface (e.g. an MCP server) rather than only chat completion. It is also the basis of the authentication/authorization probes (`mcptool.TokenValidation`, `mcptool.FunctionAuthorization`), which adjudicate by **response differential**: submitted values are masked out of the target's own responses and those responses are compared to each other, so no verdict rests on a success string, a token format, or any particular value. A response that itself reads as a refusal is scored safe — the probe value reached nothing — and where the control is a successful lower-privilege call, a SECOND independent unprivileged control isolates privilege from mere response variation. This is distinct from the model-facing tool wire layer (`Conversation.Tools`/`Message.ToolCalls`), which presents probe-defined tools *to* an LLM and executes nothing: `ToolInvoker` invokes REAL tools on the backend. It is the basis for the `internal/probes/mcptool/*` probes (broken object-level authorization via `mcptool.BOLA`, injection-into-a-sink via `mcptool.Injection`, `mcptool.SSRF` against tool backends, and response credential leakage via `mcptool.ResponseLeak`). `ListTools` **fails closed on a truncated enumeration**: it returns the pages gathered so far together with an error wrapping `types.ErrCatalogTruncated`, so a caller that ignores the error cannot mistake a partial catalog for the target's whole tool surface. Probes should let that error skip the target — reporting "could not enumerate the surface" is correct where scanning a prefix and reporting clean is a false negative. A truncated catalog is also never memoized, so a later caller gets a fresh full walk.
- **MCPReconnaissance** (`pkg/types/mcp_recon.go`): `MCPInventory()` — declares that the target's full MCP attack surface (declared capabilities, negotiated protocol version, server instructions, and the tool/resource/prompt catalog) can be enumerated from the connected session. Implemented by the `mcp.MCP` generator and consumed by the `recon.MCP` reconnaissance module. Assembles raw descriptive data only — it renders no verdict.

  Catalog enumeration follows `nextCursor` across **all** pages of `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list`, because a server that paginates its catalog would otherwise be silently under-scanned (page one tested, later-page tools never touched, target reported clean). Each enumeration is bounded independently — per catalog, so a slow `tools/list` cannot starve the others — by a page cap, cursor-repeat detection, a wall-clock budget (10× `request_timeout`), and a total-item cap. `request_timeout` applies **per page**, not to a whole walk, and the configured rate limit is charged per page rather than once per session.

  Any enumeration that stops early is recorded in `MCPInventory.Incomplete` (the catalog names), queryable via `IsComplete()` and the per-catalog `IsCatalogComplete(types.MCPCatalog*)`. **A non-empty `Incomplete` makes the inventory a lower bound on the target's surface, not a description of it** — a hostile server can halt enumeration after a benign prefix, so a consumer that scores only what was collected would report clean on a surface it never saw. Prefer `IsCatalogComplete` over `IsComplete` when you depend on only part of the inventory: discarding a complete tool catalog because an unrelated prompts enumeration failed forces a redundant walk that can itself fail closed. Recon renders no verdict, so completeness is recorded as a fact here and acted on by consumers.
- **MCPPrimitiveReader** (`pkg/types/mcp_primitives.go`): `ReadResource()` / `GetPrompt()` — declares that the target exposes the MCP content-bearing primitives BEYOND tools. `ToolInvoker` covers only tools/list + tools/call, and `MCPReconnaissance` enumerates the resource/prompt catalog but never fetches the CONTENT behind an entry; this interface adds that retrieval. Both calls are outbound (same direction as tools/call), so it introduces no new protocol direction — server-initiated callbacks (sampling/createMessage, elicitation/create) remain unimplemented. Note the denial contract: resources/read and prompts/get have no application-level error flag like `ToolResult.IsError`, so a refusal arrives as a Go error — probes treat an error as the denial signal and a returned body as acceptance. It is the basis for the `internal/probes/mcpprimitive/*` probes (`mcpprimitive.ResourceInjection`, `mcpprimitive.PromptTemplateInjection`, `mcpprimitive.ContentLeak`). The first two attack the caller-controlled parameters of those calls (sinks); `ContentLeak` instead reads every non-tool surface NORMALLY — advertised resources, resource templates expanded with a benign value, prompt templates rendered with benign arguments, and the `initialize` instructions — and scores what comes back with the shared `mcpsecrets.Credential` detector (OWASP MCP01). Catalog descriptions/titles are deliberately EXCLUDED: `mcpsecrets.Credential` keys off a credential-shaped name followed by a colon and a value, and a docstring's `Args:` block is also `name: description`, so scoring declared metadata false-positives on ordinary parameter documentation (measured against DVMCP challenges 7 and 9). Restoring that surface needs a value-shape guard in the detector, which would also benefit the config and tool-response surfaces. Sink and secret-disclosure are separate findings over one surface, mirroring `mcptool.Injection` vs `mcptool.ResponseLeak`: probe names become published risk slugs, so a credential exposure must not be filed under a traversal/SSRF write-up.
- **MCPEndpoint** (in `pkg/types/mcp_endpoint.go`): declares that the generator connects to an HTTP-based MCP target and exposes the plumbing transport-layer probes need — `EndpointURL()`, `Transport()` (kind: "http"/"sse"), `HTTPClient()` (with the generator's proxy / TLS / injected headers), `AnonymousHTTPClient()` (same transport but WITHOUT header injection, for probes that model an unauthenticated attacker), and `ProxyURL()`. Transport-layer probes (`mcptransport.OriginValidation`, `mcptransport.SSESessionHijack`, `mcptransport.UnauthenticatedAccess`) type-assert this so raw-HTTP checks still inherit proxy config and honour operator-configured credential boundaries.
- **`mcpprobe.CredentialReporter`** (`internal/mcpprobe/credentials.go`): `ConfiguredCredentialHeaders()` — reports, by header NAME only and never by value, whether the operator configured credentials for the target. Satisfied **structurally** (Go implicit interfaces), so it lives in the shared probe kit rather than `pkg/types` and the generator package need not import it; `mcp.MCP` implements it from its `headers` / `api_key` config.

  It exists because an unauthenticated-access finding is only meaningful as a **differential**. "The anonymous session worked" is trivially true against a target nobody supplied credentials for, and cannot be recovered from the target: a server with no authentication is indistinguishable on the wire from one whose auth layer never runs. Nor can it be recovered from `MCPEndpoint` — `HTTPClient` and `AnonymousHTTPClient` differ only in a `RoundTripper` the caller cannot look inside, and the credential-injecting transport withholds headers from any host but the configured endpoint, so a probe-local sink observes nothing. An empty result (or an unimplemented method) means "cannot assess", which is a **skip with a stated reason, never a clean pass**.

### Reconnaissance (pkg/recon/)

Reconnaissance is a **first-class activity distinct from probing**: it *measures* (gathers descriptive facts) and renders no verdict, whereas probes produce scored attempts. The distinction is enforced by the type system — a reconnaissance module returns `[]output.Observation`, never a score.

- **Recon** (`pkg/recon/recon.go`): `Recon(ctx, gen) ([]output.Observation, error)` + `Name()` — a reconnaissance module (e.g. `recon.MCP` in `internal/recon/mcp/`). It gates on the target's capability (type-asserting an optional interface such as `MCPReconnaissance`) and returns no observations for inapplicable targets. Results flow into a shared, concurrency-safe `recon.Store`.
- **Observation** (`pkg/output/output.go`): the one descriptive output type (`Type`/`Target`/`Data`/`Source`). The verdict stays the probe score; it is never re-represented as an observation.
- **ContextAwareProbe** (opt-in, `pkg/recon/context.go`): `SetContext(ProbeContext)` — a probe that consumes prior reconnaissance (the "scan once, reuse everywhere" model). The runner delivers the `ProbeContext` before probing — both the shared observation `Store` (`Recon`) and the `Observed` value store, which holds the scalars seen in tool responses so far so a value one tool handed out can fill another tool's argument that no schema could supply. Probes that don't implement it structurally cannot see either. `Observed` is partitioned by the identity that observed a value, and crossing identities is a separate, differently-named call, so a probe cannot accidentally fill an argument with another identity's value and manufacture the cross-identity access an authorization probe exists to detect. `mcptool.Injection`/`SSRF` use it to reuse a prior MCP inventory instead of re-enumerating the tool surface — but **only when that inventory's tools catalog is complete** (`IsCatalogComplete(types.MCPCatalogTools)`). A truncated catalog is skipped in favour of a live enumeration, which itself fails closed, so reuse can never silently narrow the surface a probe scores.
- **ContextAwareRecon** (opt-in, `pkg/recon/context.go`): `SetContext(ProbeContext)` — the recon-side parallel of `ContextAwareProbe`: a reconnaissance module that composes over *earlier* observations (recon-consumes-recon). `recon.Run` injects the shared `Store` before each module runs, so a later module reads what an earlier one emitted. `recon.MCPIdentifiers` uses it to read a prior `recon.MCP` inventory rather than re-enumerating the tool surface.
- **`recon.MCPIdentifiers`** (`internal/recon/mcp/identifiers.go`): the second MCP recon module — it discovers, per identity, which of a target's tools return objects for which identifiers, by CALLING them (harvest → offer each value to each identifier-shaped parameter → keep the pairs whose answer differs from that slot's not-found answer). Which tools hand out identifiers and which accept them is a property of the server's behaviour, not of its names, so nothing is classified up front. This establishes the ownership ground truth that downstream authorization probes (`mcptool.BOLA`) need. Ownership is the enumeration set-difference across identities, not response parsing. It **refuses a truncated tool catalog** on both paths (a stored inventory whose tools catalog is incomplete, and a live `ListTools` returning `types.ErrCatalogTruncated`): because `mcptool.BOLA` emits nothing when there are no identifiers, a partial catalog missing the real getter would otherwise make BOLA report a clean no-op against a surface that was never examined.
- **`llm.Base`** (`internal/recon/llm/llm.go`): embeddable navigator-LLM plumbing for building LLM-driven recon modules — lazy generator creation (deterministic paths need no LLM config), system/user prompting, JSON decoding, and judge/credential reuse. `recon.MCPIdentifiers` embeds it for `SetContext` and prior-observation access; it does NOT use an LLM to classify tools — name/LLM classification was removed in favour of calling tools and reading the answer.
- **`recon.MCPConfig`** (`internal/recon/mcpconfig/mcpconfig.go`): collects MCP server *configuration* — from an inline string, a file, or a walked directory of config files — and emits each source as an `output.Observation`. Unlike the capability-gated modules above it is **deliberately target-independent** (the recon contract sanctions modules that operate regardless of the target; here it reads local config files and ignores the generator). It feeds the `mcpconfig.CredentialExposure` context-aware probe, which scores the collected config with the `mcpsecrets.Credential` detector (OWASP MCP01).

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
  mcpprobe/         Shared MCP probe kit: computed-arithmetic canaries, shell-command payload families, the out-of-band callback collector, the anonymous-session helper + CredentialReporter capability, and the target-declared / target-disclosed value extractors used by the auth-authz probes (used by probes/mcptool, probes/mcpprimitive and probes/mcptransport)
  recon/            Reconnaissance modules (recon/mcp — MCP attack-surface enumeration + per-identity identifier harvesting; recon/mcpconfig — MCP config-file collection; recon/llm — navigator-LLM base for LLM-driven recon)
  toolsig/          The single reader of a tool's JSON Schema. Turns an inputSchema into concrete call SIGNATURES (a tool gated behind a discriminator has more than one, and they are not interchangeable), with parameters addressed by path (params.record_id, filters[0].field) so one nested inside an object or an array element is reachable. Also holds the value chain (config rules → hook vars → observed → filler) that fills a call. Knows JSON Schema and nothing about attacks; probes supply the attack policy
  observed/         Per-identity store of scalars seen in tool responses, so a value one tool hands out can fill another tool's argument that no schema could supply. Values are partitioned by the identity that observed them and crossing is a separate, differently-named call — an authorization probe replays one identity's object under another's session, so auto-filling across identities would manufacture the very access it tests for
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
4. Either gate on the target's capability (e.g. type-assert `types.MCPReconnaissance`), returning no observations for inapplicable targets — a module that can't operate is a skip, not an error — **or**, for a deliberately **target-independent** module (e.g. `recon.MCPConfig`, which reads local config files), ignore the generator entirely. The recon contract sanctions both.
5. To compose over earlier observations, implement `recon.ContextAwareRecon` (or embed `llm.Base`, which supplies it) and read prior observations from the injected `Store` — recon-consumes-recon
6. Per-module configuration comes from the `recon.settings` block of the YAML config, resolved by `config.ResolveReconConfig` (which also injects the global judge) and delivered as the module's `registry.Config`; see `recon.MCPIdentifiers` for generator-type/model/keyword-hint settings

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
augustus scan mcp.MCP --recon recon.MCP --probe mcptool.Injection --probe mcptool.SSRF --config '{"endpoint":"http://localhost:8000/mcp"}'

# Composed recon (recon-consumes-recon) feeding the BOLA probe; per-module settings via a recon.settings config block
augustus scan mcp.MCP --recon recon.MCP --recon recon.MCPIdentifiers --probe mcptool.BOLA --config-file bola.yaml

# MCP authentication / authorization (OWASP MCP07). UnauthenticatedAccess scores only the
# DIFFERENTIAL — credentials configured AND the credential-free session still succeeded — so
# with no credentials configured it SKIPS with a stated reason rather than firing.
augustus scan mcp.MCP \
  --probe mcptransport.UnauthenticatedAccess \
  --probe mcptool.TokenValidation --probe mcptool.FunctionAuthorization \
  --config '{"endpoint":"https://mcp.example.com/mcp","api_key":"$TOKEN","headers":{"Authorization":"Bearer $KEY"}}'

# Non-tool primitive surfaces (resources/read + prompts/get). ResourceInjection needs no
# catalog — it always sends its baseline URI payloads — but recon enriches both probes.
augustus scan mcp.MCP --recon recon.MCP \
  --probe mcpprimitive.ResourceInjection --probe mcpprimitive.PromptTemplateInjection \
  --config '{"endpoint":"http://localhost:8000/mcp"}'

# Credential exposure across every non-tool surface. Unlike the two probes above,
# ContentLeak derives ALL of its requests from the catalog, so recon (or a
# recon-capable generator) is REQUIRED: a target that cannot be enumerated is a hard
# error, never a clean pass. Note the limit of that guarantee — recon folds a failed
# list call into an empty inventory, so an enumeration that fails mid-walk arrives as
# a catalog that merely looks empty rather than as an error.
augustus scan mcp.MCP --recon recon.MCP --probe mcpprimitive.ContentLeak \
  --config '{"endpoint":"http://localhost:8000/mcp"}'
```

## Commit Convention

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`

# Adding New Components

Implementations live under `internal/`, not `pkg/`. After adding a package, run `make generate` so `pkg/register` blank-imports it (`make test` also runs the register drift guard).

## New Probe

1. Create `internal/probes/<category>/<name>.go`
2. Implement `types.Prober` interface
3. Register in `init()`: `probes.Register("category.Name", factory)`
4. Add tests in `*_test.go`
5. Run `make generate`

For YAML-based probes, create `.yaml` files in a `data/` subdirectory and use `templates.NewLoader()`. YAML templates support advanced fields consumed via the optional interfaces: `detector_config`, `secondary_detectors`, and — for tool-use/function-calling probes — `tools`, `tool_choice`, `tool_results`, and `mode: [chat, native]`. The canonical `TemplateProbe` (`pkg/templates/probe.go`) implements all optional interfaces; see `internal/probes/tooluse/data/` for tool-use attack examples (unauthorized invocation, parameter injection, selection hijacking, etc.).

Generator failures must be captured **in the attempt** (`StatusError`, non-empty `Error`), not returned from `Probe`.

## New Generator

1. Create `internal/generators/<provider>/`
2. Implement `types.Generator` interface
3. Register: `generators.Register("provider.Name", factory)`
4. Handle configuration via `registry.Config` map
5. Embed `types.UsageCounter` (satisfies the optional `UsageReporter`) and call `g.AddTokens(...)` at each usage-parse site so the provider's token counts flow into `Metrics.TokensConsumed`; leave it un-incremented if the provider returns no usage
6. Run `make generate`

## New Detector

1. Create `internal/detectors/<category>/`
2. Implement `types.Detector` interface (return scores 0.0-1.0)
3. Register: `detectors.Register("category.Name", factory)`
4. Run `make generate`

## New Reconnaissance Module

1. Create `internal/recon/<name>/`
2. Implement `recon.Recon` — return `[]output.Observation` (descriptive facts), never a score
3. Register: `recon.Register("recon.Name", factory)`
4. Either gate on the target's capability (e.g. type-assert `types.MCPReconnaissance`), returning no observations for inapplicable targets — a module that can't operate is a skip, not an error — **or**, for a deliberately **target-independent** module (e.g. `recon.MCPConfig`, which reads local config files), ignore the generator entirely. The recon contract sanctions both.
5. To compose over earlier observations, implement `recon.ContextAwareRecon` (or embed `llm.Base`, which supplies it) and read prior observations from the injected `Store` — recon-consumes-recon
6. Per-module configuration comes from the `recon.settings` block of the YAML config, resolved by `config.ResolveReconConfig` (which also injects the global judge) and delivered as the module's `registry.Config`; see `recon.MCPIdentifiers` for generator-type/model/keyword-hint settings
7. Run `make generate`

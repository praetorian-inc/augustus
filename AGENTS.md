# augustus

Canonical agent instructions for this repository. `CLAUDE.md` is a one-line pointer here; `.gemini/settings.json` lists this file. Interface catalogs, recon contracts, and layout live in `docs/agents/architecture.md`. Adding probes/generators/detectors/recon: `docs/agents/adding-components.md`. Scan CLI examples: `docs/agents/cli.md`. Product framing: `docs/agents/overview.md`.

## Build and Test Commands

```bash
make build                 # binary to bin/augustus
go build ./cmd/augustus    # alternative direct build
make test                  # go test -v -race ./...
go test ./pkg/scanner -v   # one package
go test ./... -run TestName
make test-cover            # coverage.html
make lint                  # pinned golangci-lint v2.13.1 via go run
golangci-lint fmt ./...    # gofumpt + goimports — plain go fmt fails CI
make generate              # pkg/register blank-imports from internal/
make generate-check
```

Lint is `.golangci.yml` (v2 `standard` linters plus `gofumpt`/`goimports`). CI is `.github/workflows/ci.yml`. After adding a package under `internal/`, run `make generate` or the binary will not see it; `make test` also runs the register drift guard.

## Scanner contracts

Skip is not clean. Do not score a target safe when the surface was not fully seen:

- `ListTools` wrapping `types.ErrCatalogTruncated` skips the target; never memoize a truncated catalog.
- `mcptransport.UnauthenticatedAccess` with no configured credentials skips with a reason (`mcpprobe.CredentialReporter`); anonymous success is uninterpretable.
- `mcpprimitive.ContentLeak` hard-errors if it cannot enumerate (needs recon or `types.MCPReconnaissance`). Do not score catalog titles/descriptions (`mcpsecrets.Credential` false-positives on `Args:` docs).
- Probe generator failures belong on the attempt (`StatusError`), not as `Probe()` return errors.
- `internal/observed/` values are partitioned by identity; do not auto-fill across identities.
- `VisionCapable` / `DocumentCapable` skip structurally incapable wires rather than sending text-only and reporting safe.

Implementations live under `internal/`, not `pkg/`. Ignore `CONTRIBUTING.md` paths that still say `pkg/probes/`.

## Key Patterns

- Typed config: `registry.FromMap()`
- YAML probes: `embed.FS` + `templates.Loader` / `templates.NewLoader()`
- Keyword detectors: `internal/ahocorasick/`
- Rate limit: `pkg/ratelimit/`; retry: `pkg/retry/`
- Embed `types.UsageCounter`; `AddTokens` only when the provider reports usage
- Verdict is max score across detectors (`attempt.GetEffectiveScores`)

## Commit Convention

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`.

---
title: Linting, CI & Commits
tags: [augustus, contributing, ci, lint]
type: guide
status: complete
---

# Linting, CI & Commits

> Augustus enforces a `golangci-lint`-clean, consistently formatted tree on every PR. Formatting drift fails the build, so format locally before you commit. Commits follow the conventional-commits convention.

## golangci-lint v2 config

`.golangci.yml` (golangci-lint **v2**, pinned to `v2.13.1` in the `Makefile`) configures two things:

```yaml
version: "2"
linters:
  default: standard        # errcheck, govet, ineffassign, staticcheck, unused
formatters:
  enable:
    - gofumpt              # strict superset of gofmt
    - goimports            # enforce import grouping/ordering
  settings:
    goimports:
      local-prefixes:
        - github.com/praetorian-inc/augustus
```

- **Linters**: the default `standard` set — the codebase already passes it.
- **Formatters**: `gofumpt` + `goimports`. This block is what makes CI enforce a clean format tree, including import grouping with the local-prefix above.

(`gosec` runs separately via the security workflow, not through this config.)

## Format requirement

Plain `go fmt` is **not** sufficient — it does not satisfy `gofumpt`/`goimports`. Always run:

```bash
golangci-lint fmt ./...    # apply gofumpt + goimports (exactly what CI checks)
make lint                  # run the standard linter set
```

`make lint` runs the pinned `v2.13.1` module via `go run`, so an older binary elsewhere on `PATH` cannot be selected.

## CI

CI runs `golangci-lint` via the shared `praetorian-inc/public-workflows` `go-ci.yml` reusable workflow on every PR (the repo's `.github/workflows/ci.yml` and `security.yml` watch `.golangci*`). Because the same config drives local and CI runs, a `golangci-lint fmt`-clean tree locally means CI formatting passes. Keep it clean to avoid red builds.

## Build & test before pushing

Per the contributor checklist:

```bash
make build      # confirm it compiles
make test       # race-enabled tests must pass
golangci-lint fmt ./...
make lint
```

## Conventional commits

Use conventional-commit prefixes:

| Prefix | Use |
| --- | --- |
| `feat:` | New feature/capability |
| `fix:` | Bug fix |
| `docs:` | Documentation |
| `refactor:` | Code restructuring, no behavior change |
| `test:` | Test additions/changes |

Optional scope in parentheses, e.g. `feat(probes): add tool selection hijacking probe` or `fix(detectors): stop false-positive on refusals`. Open the PR against `main` with a clear description.

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Development Setup]]
- [[Testing & Equivalence Tests]]

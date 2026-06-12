---
title: Contributing MOC
tags: [augustus, contributing, moc]
type: moc
status: complete
---

# Contributing MOC

> The hub for extending **Augustus**. Every capability — [[Probes|probe]], [[Generators|generator]], [[Detectors|detector]], [[Buffs|buff]] — is a self-registering plugin discovered at startup via an `init()` function. To add one you implement the matching interface from `pkg/types/`, call the package's `Register("category.Name", factory)` in `init()`, and add a `*_test.go`. No central wiring file to edit.

Augustus is a Go-based LLM vulnerability scanner. Contributions almost always take one of two shapes: a **YAML template** (no Go code — the canonical `TemplateProbe` provides all behavior) or a **Go implementation** (a struct satisfying an interface). Start with YAML when your attack is prompt-driven; reach for Go when you need custom logic, new transport, or new scoring.

## Contributing notes

| Note | What it covers |
| --- | --- |
| [[Development Setup]] | Clone, Go toolchain, build, run, editor/lint setup |
| [[Adding a Probe]] | `types.Prober`, `probes.Register`, optional interfaces, tests |
| [[Adding a Generator]] | `types.Generator`, config via `registry.Config`/`FromMap`, auth/env |
| [[Adding a Detector]] | `types.Detector` returning `[0,1]`, scoring guidance |
| [[Adding a Buff]] | `Buff`/`PostBuff`, registration, chaining |
| [[YAML Templates]] | Authoring YAML probes, all supported fields, tool-use examples |
| [[Testing & Equivalence Tests]] | Test layout, `make test` / `test-equiv` / `test-cover` |
| [[Linting, CI & Commits]] | golangci-lint v2, formatting gate, CI, conventional commits |

## Dev workflow at a glance

```bash
# 1. branch
git checkout -b feat/my-probe

# 2. implement + register (see the relevant note), add *_test.go

# 3. build, test, format BEFORE committing
make build
make test
golangci-lint fmt ./...     # plain `go fmt` is NOT enough for the CI gate
make lint

# 4. conventional commit, then open a PR against main
git commit -m "feat(probes): add my new probe"
```

Five-stage scan pipeline a contribution plugs into: **Probe Selection -> Buff Transform -> Generator Call -> Detector Analysis -> Result Recording** (see [[Scan Pipeline]]).

## Navigation

- [[Home]]
- [[Core Interfaces]]
- [[Plugin Registration & Registries]]
- [[Scan Pipeline]]

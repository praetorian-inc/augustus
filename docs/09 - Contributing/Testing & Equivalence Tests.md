---
title: Testing & Equivalence Tests
tags: [augustus, contributing, testing]
type: guide
status: complete
---

# Testing & Equivalence Tests

> Augustus uses standard Go `testing` with table-driven tests co-located beside the code. Unit tests are required for every new capability. The `Makefile` wraps the common runs.

## Test layout

Tests live next to the code they cover, in the same package: `internal/probes/test/test_test.go`, `internal/detectors/always/pass_test.go`, etc. Each probe/generator/detector/buff ships its own `*_test.go`. Cross-cutting integration tests live alongside the package they exercise (e.g. `pkg/buffs/integration_test.go`, `internal/probes/flipattack/integration_test.go`).

## Running tests

```bash
make test                    # go test -v -race ./...   (race detector ON)
go test ./pkg/scanner -v     # one package
go test ./... -run TestName  # one test by name (regex)
make test-cover              # coverage -> coverage.out + coverage.html
```

Race detection is on by default in `make test` — keep new concurrent code clean.

## What to test

Mirror the existing patterns:

- **Probes** — drive `Probe` with a mock generator; assert attempt fields (`Probe`, `Detector`, `Prompt`, `Outputs`, `Status`). Generator failures must be captured **in the attempt** (`StatusError`, non-empty `Error`), not returned from `Probe`. See `internal/probes/test/test_test.go`.
- **Detectors** — feed crafted `Outputs` and assert exact scores; always include negative cases (refusals/benign text scoring `0.0`) next to positive vulnerable cases.
- **Generators** — assert message shape, `n`-handling, and config/auth resolution.
- **Buffs** — assert `Transform` output (including one-to-many counts) and any `PostBuff.Untransform` round-trip.
- **Registry** — confirm your `init()` registration is reachable (a registration test exists, e.g. `internal/generators/registration_test.go`).

Aim for thorough edge-case coverage (empty input, malformed data, multi-output `n>1`).

## Equivalence tests

`make test-equiv` runs the Go-vs-Python parity suite:

```bash
make test-equiv    # go test -v ./tests/equivalence/...
```

These verify that ported capabilities produce results equivalent to the original Python reference implementation (garak-lineage probes/detectors), guarding against regressions when porting or refactoring. Run them when you change a capability that has a Python counterpart.

> **Note:** the `test-equiv` target targets `./tests/equivalence/...`. If that path is absent in your checkout, the suite has not been added for your component yet — `make test` remains the required gate for every PR.

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Adding a Probe]]
- [[Adding a Detector]]
- [[Linting, CI & Commits]]

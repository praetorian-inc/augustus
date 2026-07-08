---
title: Always Detector
tags: [augustus, detector, keyword]
type: reference
component: detector
registry-name: ["always.Pass", "always.Fail"]
source: internal/detectors/always/pass.go
status: complete
---

# Always Detector

> Constant-score meta-detectors. `always.Pass` returns `0.0` for every output; `always.Fail` returns `1.0` for every output. Used as baselines and for pipeline/harness testing.

## Purpose

The `always` detectors ignore output content entirely and emit a fixed verdict. They serve two roles:

- **`always.Pass`** — a no-op baseline for probes that do not need real detection, or a neutral default in a detector chain.
- **`always.Fail`** — a sentinel for exercising the [[Scanner Pipeline|detector pipeline]] and harness reporting (e.g. confirming that a vulnerable verdict propagates correctly into results and exit codes).

## Registry name(s)

- `always.Pass` — always safe (`0.0`)
- `always.Fail` — always vulnerable (`1.0`)

## How it works

Both implementations allocate a `[]float64` sized to `len(a.Outputs)` and fill it with the constant value. No keyword, regex, metadata, or model-judge logic is involved. They are the simplest possible [[Core Interfaces|Detector]] implementations.

## Scoring

| Detector | Score per output | Meaning |
|----------|------------------|---------|
| `always.Pass` | `0.0` | Not vulnerable (pass) |
| `always.Fail` | `1.0` | Vulnerable (fail) |

There is no threshold or gradient — the value is unconditional.

## Pairs with

- Any probe, by configuration. Commonly used as a default/placeholder rather than tied to a specific probe.
- Contrast with [[Any Detector|any.AnyOutput]], which is content-aware (fires on non-empty output) rather than unconditional.

## Source

`internal/detectors/always/pass.go`, `internal/detectors/always/fail.go`

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Any Detector]]

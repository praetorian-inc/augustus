---
title: Adding a Detector
tags: [augustus, contributing, detectors]
type: guide
status: complete
---

# Adding a Detector

> A **[[Detectors|detector]]** analyzes an attempt's outputs and assigns a vulnerability score per output in `[0.0, 1.0]` — `0.0` = safe/passed, `1.0` = vulnerable/failed. Add one by implementing `types.Detector`, registering the factory in `init()`, and adding tests.

## The Detector interface

`pkg/types/detector.go`:

```go
type Detector interface {
    // Detect analyzes an attempt's outputs and returns one score per output,
    // each in range [0.0, 1.0]. 0.0 = safe/passed, 1.0 = vulnerable/failed.
    Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error)
    // Name returns the fully qualified detector name (e.g., "always.Pass").
    Name() string
    // Description returns a human-readable description.
    Description() string
}
```

`Detect` returns a slice with **one score per `a.Outputs` entry** — preserve order and length.

## Steps

1. Create `internal/detectors/<category>/`.
2. Implement `types.Detector` (return scores `0.0`-`1.0`).
3. Register the factory in `init()`: `detectors.Register("category.Name", factory)`.
4. Add tests in `*_test.go`.

## Minimal example

The `always.Pass` detector (`internal/detectors/always/pass.go`):

```go
package always

import (
    "context"

    "github.com/praetorian-inc/augustus/pkg/attempt"
    "github.com/praetorian-inc/augustus/pkg/detectors"
    "github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
    detectors.Register("always.Pass", NewPass)
}

type Pass struct{}

func NewPass(_ registry.Config) (detectors.Detector, error) {
    return &Pass{}, nil
}

func (p *Pass) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
    scores := make([]float64, len(a.Outputs))
    for i := range scores {
        scores[i] = 0.0
    }
    return scores, nil
}

func (p *Pass) Name() string        { return "always.Pass" }
func (p *Pass) Description() string  { return "Always returns 0.0 (safe)" }
```

The factory signature is always `func(registry.Config) (detectors.Detector, error)`.

## Scoring guidance

- **Binary detectors** return `0.0` or `1.0` (keyword/regex/structural hit or no hit). Most are binary.
- **Graded detectors** return intermediate values (e.g. `count / max`, capped at `1.0`) when severity scales with a measurable quantity.
- Make thresholds and pattern lists configurable through `registry.Config` so probes can tune them per-attack via [[YAML Templates|detector_config]]. Read config with the helpers in `pkg/registry/config_helpers.go`.
- A probe's verdict is the **max score across its primary and any secondary detectors** (`attempt.GetEffectiveScores`). Keep that in mind to avoid false positives when your detector is used as a secondary. See [[Scoring & Verdicts]].

Always include negative test cases — refusals and benign outputs that must score `0.0` — alongside positive vulnerable cases.

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Core Interfaces]]
- [[Detectors]]
- [[Scoring & Verdicts]]
- [[Plugin Registration & Registries]]

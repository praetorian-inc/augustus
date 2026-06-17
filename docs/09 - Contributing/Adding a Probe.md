---
title: Adding a Probe
tags: [augustus, contributing, probes]
type: guide
status: complete
---

# Adding a Probe

> A **[[Probes|probe]]** generates attack prompts, sends them through a [[Generators|generator]], and returns `[]*attempt.Attempt`. Add one by implementing `types.Prober`, registering it in an `init()`, and adding a `*_test.go`. For prompt-only attacks prefer a [[YAML Templates|YAML template]] (no Go code).

## The Prober interface

The minimal contract every probe satisfies (`pkg/types/prober.go`):

```go
type Prober interface {
    // Probe executes the attack against the generator.
    Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
    // Name returns the fully qualified probe name (e.g., "test.Blank").
    Name() string
}
```

`probes.Prober` and `probes.Generator` are type aliases for the canonical `types.*` definitions, so either import works.

## Steps

1. Create `internal/probes/<category>/<name>.go`.
2. Implement `types.Prober` (often by embedding `probes.NewSimpleProbe`, which handles the prompt loop, attempt construction, and error capture for you).
3. Register the factory in `init()`: `probes.Register("category.Name", factory)`.
4. Add `internal/probes/<category>/<name>_test.go`.

## Minimal Go example

This is the real `test.Test` probe (`internal/probes/test/test.go`) — the simplest pattern, built on `SimpleProbe`:

```go
package test

import (
    "github.com/praetorian-inc/augustus/pkg/probes"
    "github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
    probes.Register("test.Test", NewTest)
}

var defaultTestPrompts = []string{"", "The quick brown fox jumps over the lazy dog"}

type Test struct {
    *probes.SimpleProbe
}

func NewTest(cfg registry.Config) (probes.Prober, error) {
    prompts := defaultTestPrompts
    if p, ok := cfg["prompts"].([]string); ok {
        prompts = p
    }
    return &Test{
        SimpleProbe: probes.NewSimpleProbe(
            "test.Test",                 // name
            "send some test strings",    // goal
            "always.Pass",               // primary detector
            "Test probe description",    // description
            prompts,
        ),
    }, nil
}
```

The factory signature is always `func(registry.Config) (probes.Prober, error)`. The first `SimpleProbe` arg is the registry name and **must** match the string passed to `Register`. The `always.Pass` argument is the recommended primary detector (see [[Adding a Detector]]).

## Optional interfaces

Probes can implement these (all in `pkg/types/prober.go`) for richer behavior; the scanner discovers them by type assertion, so you only implement what you need:

- **ProbeMetadata** — `Description()` / `Goal()` / `GetPrimaryDetector()` / `GetPrompts()` for reporting and filtering. (`SimpleProbe` already provides these.)
- **ProbeDetectorConfig** — `GetDetectorConfig() map[string]any`: per-probe overrides merged on top of the global detector config; the scanner then builds a dedicated detector instance for the probe.
- **ProbeSecondaryDetectors** — `GetSecondaryDetectors() []SecondaryDetector`: extra detectors run alongside the primary. The attempt verdict is the **max score across all detectors** (`attempt.GetEffectiveScores`), so a secondary hit alone marks the attempt vulnerable. See [[Scoring & Verdicts]].
- **ProbeTools** — `GetTools() []map[string]any` / `GetToolChoice() string`: declare function-calling tool schemas for tool-use/agent probes, sent via the native wire layer (`internal/attackengine/toolcalls.go`).

## Tests

Drive `Probe` with a mock generator and assert on the returned attempts (probe name, detector, prompt, outputs, status). Generator errors should be captured **in the attempt** (`StatusError`, non-empty `Error`), not returned from `Probe`. Pattern from `internal/probes/test/test_test.go`:

```go
attempts, err := p.Probe(context.Background(), gen)
if err != nil { t.Fatalf("Probe() error = %v", err) }
if attempts[0].Probe != "test.Test" { t.Errorf("wrong probe name") }
if attempts[0].Detector != "always.Pass" { t.Errorf("wrong detector") }
```

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Core Interfaces]]
- [[YAML Templates]]
- [[Plugin Registration & Registries]]
- [[Adding a Detector]]
- [[Scoring & Verdicts]]

---
title: Core Interfaces
aliases: ["Probe Detector Config", "Probe Secondary Detectors", "Probe Tools", "Probe Metadata"]
tags: [augustus, architecture, interfaces]
type: reference
status: complete
---

# Core Interfaces

Every capability in Augustus implements one of four interfaces defined canonically in `pkg/types/`. Other packages import these via type aliases for backward compatibility. This note is the hub the component concept notes ([[Probes]], [[Generators]], [[Detectors]], [[Buffs]]) link back to.

## Prober

Generates attack prompts. Defined in `pkg/types/prober.go`. The minimal interface follows the Interface Segregation Principle — the [[Concurrency & Scanner|Scanner]] only needs `Probe` and `Name`.

```go
type Prober interface {
    // Probe executes the attack against the generator.
    Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
    // Name returns the fully qualified probe name (e.g., "test.Blank").
    Name() string
}
```

## Generator

Wraps an LLM API. Defined in `pkg/types/generator.go`. Takes a `*attempt.Conversation`, returns model messages (see [[Attempt & Conversation Model]]).

```go
type Generator interface {
    // Generate sends a conversation to the model and returns responses.
    // n specifies the number of completions to generate.
    Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
    // ClearHistory resets any conversation state in the generator.
    ClearHistory()
    Name() string
    Description() string
}
```

## Detector

Scores outputs. Defined in `pkg/types/detector.go`. Returns one score per output, each in `[0.0, 1.0]` where `0.0` = safe/passed and `1.0` = vulnerable/failed.

```go
type Detector interface {
    // Detect analyzes an attempt's outputs and returns scores.
    Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error)
    Name() string
    Description() string
}
```

## Buff

Transforms prompts before sending. Defined in `pkg/buffs/buff.go`. Uses Go 1.23+ `iter.Seq` for lazy generation.

```go
type Buff interface {
    Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error)
    Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt]
    Name() string
    Description() string
}
```

`PostBuff` (same file) optionally extends `Buff` to post-process generator outputs before detection via `HasPostBuffHook()` and `Untransform(ctx, a)`.

## Optional probe interfaces

A prober may also implement any of these (all in `pkg/types/prober.go`). Clients detect support via type assertion.

| Interface | Method(s) | Purpose |
|---|---|---|
| `ProbeMetadata` | `Description() string`, `Goal() string`, `GetPrimaryDetector() string`, `GetPrompts() []string` | Introspection for reporting, filtering, UI |
| `ProbeDetectorConfig` | `GetDetectorConfig() map[string]any` | Per-probe detector config overrides, merged on top of global/YAML config |
| `ProbeSecondaryDetectors` | `GetSecondaryDetectors() []SecondaryDetector` | Run extra detectors alongside the primary; verdict = MAX score across all |
| `ProbeTools` | `GetTools() []map[string]any`, `GetToolChoice() string` | Declare function-calling tool schemas for tool-use/agent probes |

```go
type SecondaryDetector struct {
    Name   string         // fully qualified detector name
    Config map[string]any // optional per-detector overrides, merged on top of global
}
```

Because the attempt verdict reflects the **max score across all detectors** ([[Scan Pipeline]], `attempt.GetEffectiveScores`), a secondary detector hit alone marks an attempt vulnerable. `GetTools`/`GetToolChoice` schemas are sent via the native wire layer in `internal/attackengine/toolcalls.go` and carried on `Conversation.Tools` / `Conversation.ToolChoice`.

---

Implementations register via [[Plugin Registration & Registries]]. Back to [[Architecture MOC]] · [[Home]]

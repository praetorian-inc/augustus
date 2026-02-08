# pkg/types

Canonical interface definitions for Augustus components.

## Interfaces

### Prober (core execution)

```go
type Prober interface {
    Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
    Name() string
}
```

**When to implement:** Every probe must implement `Prober`. This is the minimal
interface required for probe execution by the scanner.

### ProbeMetadata (optional metadata)

```go
type ProbeMetadata interface {
    Description() string
    Goal() string
    GetPrimaryDetector() string
    GetPrompts() []string
}
```

**When to implement:** Implement `ProbeMetadata` when your probe needs to expose
metadata for reporting, filtering, or UI display. This is optional -- probes that
only need execution can implement just `Prober`.

### Why Two Interfaces?

This follows the **Interface Segregation Principle (ISP)**. Clients that only
execute probes (like `Scanner`) don't pay for metadata methods they don't use.
Clients that need metadata (like report generators) can check for it.

### Type Assertion Pattern

Use type assertion to check if a `Prober` also provides metadata:

```go
prober := getProber() // returns types.Prober

// Check for metadata support
if pm, ok := prober.(types.ProbeMetadata); ok {
    fmt.Println(pm.Description())
    fmt.Println(pm.Goal())
    fmt.Println(pm.GetPrimaryDetector())
} else {
    // Probe does not provide metadata -- that's fine
}
```

### Generator

```go
type Generator interface {
    Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
    ClearHistory()
    Name() string
    Description() string
}
```

All LLM backends implement `Generator`. Generators wrap API clients with
authentication, rate limiting, and conversation management.

### Detector

```go
type Detector interface {
    Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error)
    Name() string
    Description() string
}
```

Detectors analyze LLM outputs and assign vulnerability scores (0.0 = safe, 1.0 = vulnerable).

## Backward Compatibility

Other packages (e.g., `pkg/probes`, `pkg/scanner`) re-export these interfaces
as type aliases:

```go
// In pkg/probes/probe.go:
type Prober = types.Prober
type ProbeMetadata = types.ProbeMetadata
```

This ensures existing imports continue to work while the canonical definitions
live here.

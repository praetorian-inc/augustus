---
title: Adding a Generator
tags: [augustus, contributing, generators]
type: guide
status: complete
---

# Adding a Generator

> A **[[Generators|generator]]** wraps an LLM API behind a common interface: it turns an `*attempt.Conversation` into `[]attempt.Message`. Add one by implementing `types.Generator`, registering the factory in `init()`, and reading credentials from `registry.Config` with an environment-variable fallback.

## The Generator interface

`pkg/types/generator.go`:

```go
type Generator interface {
    // Generate sends a conversation to the model and returns n completions.
    Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
    // ClearHistory resets any conversation state in the generator.
    ClearHistory()
    // Name returns the fully qualified generator name (e.g., "openai.GPT4").
    Name() string
    // Description returns a human-readable description.
    Description() string
}
```

## Steps

1. Create `internal/generators/<provider>/` and a `.go` file.
2. Implement `types.Generator`.
3. Register the factory in `init()`: `generators.Register("provider.Name", factory)`.
4. Add tests in `*_test.go`.

## Minimal example

The `test.Single` generator (`internal/generators/test/single.go`) shows the full shape:

```go
package test

import (
    "context"
    "fmt"

    "github.com/praetorian-inc/augustus/pkg/attempt"
    "github.com/praetorian-inc/augustus/pkg/generators"
    "github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
    generators.Register("test.Single", NewSingle)
}

type Single struct{}

func NewSingle(_ registry.Config) (generators.Generator, error) {
    return &Single{}, nil
}

func (s *Single) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
    if n > 1 {
        return nil, fmt.Errorf("test.Single refuses multiple generations (requested %d)", n)
    }
    return []attempt.Message{attempt.NewAssistantMessage("ELIM")}, nil
}

func (s *Single) ClearHistory()        {}
func (s *Single) Name() string         { return "test.Single" }
func (s *Single) Description() string  { return "Returns fixed string for testing" }
```

The factory signature is always `func(registry.Config) (generators.Generator, error)`.

## Configuration via registry.Config

`registry.Config` is a `map[string]any`. Read it with the typed helpers in `pkg/registry/config_helpers.go` (`GetString`, `GetInt`, `GetFloat64`, `GetFloat32`, `GetStringSlice`, ...) rather than hand-rolled type switches. For typed config structs, adapt to/from the map with `registry.FromMap()` / `*FromMap()` constructors (e.g. `BaseConfigFromMap`, `ReasoningConfigFromMap`).

Users pass config on the CLI: `--config '{"api_key":"...","model":"gpt-4o"}'`.

## Auth / env conventions

Resolve API keys from config first, then fall back to a provider environment variable. Use the shared helper so the error message is consistent:

```go
apiKey, err := registry.GetAPIKeyWithEnv(cfg, "OPENAI_API_KEY", "openai")
if err != nil {
    return nil, err // "openai generator requires 'api_key' configuration or OPENAI_API_KEY environment variable"
}
```

Use `GetOptionalAPIKeyWithEnv` when the key is optional (returns `""` without error). If you rename or retire a config key, add it to `registry.DeprecatedKeys` so `WarnDeprecatedKeys` surfaces migration guidance once per process.

## Native tool calling

If your provider supports function calling, translate a probe's `GetTools()` map into the provider wire format inside `Generate`. The conversation carries declared tools; see `internal/attackengine/toolcalls.go` and [[Tool Use & Function Calling]].

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Core Interfaces]]
- [[Generators]]
- [[Plugin Registration & Registries]]
- [[Attempt & Conversation Model]]

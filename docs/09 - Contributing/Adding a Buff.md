---
title: Adding a Buff
tags: [augustus, contributing, buffs]
type: guide
status: complete
---

# Adding a Buff

> A **[[Buffs|buff]]** transforms a probe's prompts *before* they reach the generator (encoding, translation, reframing). Add one by implementing the `Buff` interface, registering the factory in `init()`, and — if your buff needs to post-process model output before scoring — also implementing `PostBuff`.

## The Buff interface

`pkg/buffs/buff.go`:

```go
type Buff interface {
    // Buff transforms a slice of attempts, returning modified versions.
    Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error)
    // Transform yields transformed attempts from a single input.
    // Uses iter.Seq for lazy generation (Go 1.23+).
    Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt]
    // Name returns the buff's fully qualified name.
    Name() string
    // Description returns a human-readable description.
    Description() string
}
```

`Transform` is the core: it yields one or more transformed attempts from a single input (a buff may be one-to-many, e.g. paraphrase producing several variants). `Buff` applies `Transform` across a slice.

## PostBuff (optional)

When a buff mutates the prompt into a form the model answers in another language/encoding, implement `PostBuff` to translate the response back to English **before** detection runs:

```go
type PostBuff interface {
    Buff
    HasPostBuffHook() bool
    Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error)
}
```

Examples: low-resource-language and constructed-language buffs back-translate responses so detectors score English text.

## Steps

1. Create `internal/buffs/<category>/`.
2. Implement `Buff` (and `PostBuff` if you need post-generation processing).
3. Register the factory in `init()`: `buffs.Register("category.Name", factory)`.
4. Add tests in `*_test.go`.

## Registration pattern

The factory signature is `func(registry.Config) (buffs.Buff, error)`:

```go
func init() {
    buffs.Register("encoding.Base64", NewBase64)
}

func NewBase64(cfg registry.Config) (buffs.Buff, error) {
    return &Base64Buff{ /* ... */ }, nil
}
```

## Chaining

Buffs are composable: multiple `--buff` flags apply in sequence (probe -> buff -> buff -> ... -> generator). The scanner wraps the probe in a `BuffedProber` (`pkg/buffs/prober.go`), which runs the buff chain on each attempt, calls the generator, then runs any `PostBuff.Untransform` hooks in reverse before detection. An empty chain is zero-overhead. Keep each buff a single, well-named transform so chains stay predictable. Usage and chaining details: [[Buffs in Practice]].

```bash
bin/augustus scan openai.OpenAI --all --buff encoding.Base64
```

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Core Interfaces]]
- [[Buffs]]
- [[Buffs in Practice]]
- [[Scan Pipeline]]

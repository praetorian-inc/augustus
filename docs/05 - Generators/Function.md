---
title: Function
tags: [augustus, generator, framework]
type: reference
component: generator
registry-name:
  - "function.Single"
  - "function.Multiple"
source: internal/generators/function/function.go
status: complete
---

# Function

> Programmatic [[Generators|generator]] that wraps a user-supplied Go function as the "model" — for testing, mocking, and embedding Augustus in larger Go programs. Not intended for CLI use.

## Purpose

Lets Go callers plug an arbitrary function into the scan pipeline as a [[Core Interfaces|Generator]]. The wrapped function receives the conversation's last prompt (`conv.LastPrompt()`) and returns response strings, which are converted to `attempt.Message` values. Two variants cover single- vs multiple-response semantics.

## Registry name(s)

- `function.Single` — factory `NewSingle`; wraps `func(string) []string`. Called once regardless of `n`; returns only the first response.
- `function.Multiple` — factory `NewMultiple`; wraps `func(string, int) []string`. Receives `n` and is expected to return `n` responses.

## Configuration

Configured via the `registry.Config` map with a single key:

| Key | Type | Notes |
|-----|------|-------|
| `function` | `func(string) []string` (Single) or `func(string, int) []string` (Multiple) | **Required**; type-checked at construction. Wrong signature returns an error. |

Because the value must be a live Go function, this generator is constructed programmatically, not from YAML/JSON or the CLI. See [[Provider Configuration]].

## Authentication

- None.

## Notes

- **Single** ignores `n>1` and returns one message; empty/nil results become a single empty assistant message.
- **Multiple** returns one message per returned string; a nil result yields `n` empty messages.
- Both are stateless — `ClearHistory()` is a no-op.
- **Tool-use / streaming / multimodal**: not applicable.
- Useful as a deterministic stand-in when writing tests for [[Probes]] and [[Detectors]].

## Source

`internal/generators/function/function.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]]

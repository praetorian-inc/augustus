---
title: Test Generator
tags: [augustus, generator, local]
type: reference
component: generator
registry-name: "test.*"
source: internal/generators/test/blank.go
status: complete
---

# Test Generator

> A family of mock generators that produce deterministic or canned output without contacting any LLM. Used to verify harness wiring, probe/detector logic, and edge-case handling (empty responses, single-generation constraints, multimodal input) offline and in CI.

## Purpose

The `test` package registers several lightweight [[Core Interfaces|Generator]] implementations. None require credentials or network access, making them ideal for unit tests, examples, and connectivity checks of the [[Scan Pipeline]].

## Registry name(s)

| Name | Constructor | Behavior |
|------|-------------|----------|
| `test.Blank` | `NewBlank` | always returns `n` empty messages (simplest case) |
| `test.Nones` | `NewNones` | always returns `n` empty messages (tests handling of missing responses) |
| `test.Single` | `NewSingle` | returns fixed string `"ELIM"`; **errors if `n > 1`** (tests single-generation constraints) |
| `test.Repeat` | `NewRepeat` | echoes the last prompt, optionally with a `prefix` |
| `test.Lipsum` | `NewLipsum` | returns random Lorem Ipsum text (1–3 sentences); tests varying non-zero output |
| `test.BlankVision` | `NewBlankVision` | accepts text+image input, returns empty text (tests multimodal probe handling) |

## Configuration

Almost all take no configuration. The exception:

| Generator | Key | Type | Notes |
|-----------|-----|------|-------|
| `test.Repeat` | `prefix` | string | optional prefix prepended to the echoed prompt |

## Authentication

None — no network access.

## Notes

- **Determinism**: `Blank`, `Nones`, `Single`, `Repeat` are deterministic; `Lipsum` is randomized (seeded from time).
- **Constraint testing**: `test.Single` deliberately rejects `n > 1` to exercise generators that cannot batch.
- **Multimodal**: `test.BlankVision` exists to validate text+image probe paths without a real vision model.
- **Stateless**: all `ClearHistory()` implementations are no-ops.

## Source

- `internal/generators/test/blank.go` — `Blank` (package doc lives here)
- `internal/generators/test/nones.go` — `Nones`
- `internal/generators/test/single.go` — `Single`
- `internal/generators/test/repeat.go` — `Repeat`
- `internal/generators/test/lipsum.go` — `Lipsum`
- `internal/generators/test/blankvision.go` — `BlankVision`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Scan Pipeline]]

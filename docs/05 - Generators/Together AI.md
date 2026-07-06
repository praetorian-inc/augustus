---
title: Together AI
tags: [augustus, generator, aggregator]
type: reference
component: generator
registry-name: "together.Together"
source: internal/generators/together/together.go
status: complete
---

# Together AI

> Generator for [Together.ai](https://www.together.ai/), an inference aggregator hosting many open-source models behind an OpenAI-compatible chat-completions API. Implemented in ~10 lines by delegating entirely to the [[OpenAI-Compatible]] infrastructure.

## Purpose

`together.Together` is a thin wrapper: `NewTogether` calls `openaicompat.NewGenerator` with a static `ProviderConfig`, producing a `CompatGenerator`. All request building, message conversion, and error handling come from the shared [[OpenAI-Compatible]] package. It serves as the canonical minimal example of an OpenAI-compatible provider.

## Registry name(s)

- `together.Together` → `NewTogether` (`internal/generators/together/together.go`)

`ProviderConfig` values:
- Provider: `together`
- Default base URL: `https://api.together.xyz/v1`
- API-key env var: `TOGETHER_API_KEY`

## Configuration

Handled by `openaicompat.NewGenerator` (see [[OpenAI-Compatible]] for full detail):

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `model` | string | yes | — | Together model name |
| `api_key` | string | yes | `TOGETHER_API_KEY` env | |
| `base_url` | string | no | `https://api.together.xyz/v1` | |
| `temperature` | float | no | 0.7 | |
| `max_tokens` | int/float | no | unset | |
| `top_p` | float | no | unset | |

## Authentication

API-key bearer auth via the embedded `go-openai` client; key from `api_key` config or `TOGETHER_API_KEY`. See [[Provider Configuration]].

## Notes

- **Tool-use**: not supported (compat providers do not wire `conv.Tools`; see [[OpenAI-Compatible]]).
- **Streaming**: not used.
- **Multiple generations**: passed through as `N` to the chat-completions API.
- **Stateless**: `ClearHistory()` is a no-op.

## Source

- `internal/generators/together/together.go` — registration + `NewTogether`
- `internal/generators/openaicompat/openaicompat.go` — shared `CompatGenerator` implementation

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible]]
- [[OpenAI]]

---
title: OpenAI
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "openai.OpenAI"
source: internal/generators/openai/openai.go
status: complete
---

# OpenAI

> Wraps the OpenAI API for both modern chat-completion models (GPT-4, GPT-4o, GPT-3.5-turbo) and legacy text-completion models (gpt-3.5-turbo-instruct, davinci-002). The most widely reused generator in Augustus — its message conversion, error handling, and model tables are shared with the [[OpenAI-Compatible]] infrastructure and many other providers.

## Purpose

`OpenAI` implements the [[Core Interfaces|Generator]] interface (`*attempt.Conversation → []attempt.Message`) on top of the `github.com/sashabaranov/go-openai` SDK. It auto-detects whether the configured model uses the chat API or the legacy completions API and routes the request accordingly. Unknown models default to the chat API.

Tool-use / function-calling is fully supported here: when a probe declares tools (see [[Core Interfaces|ProbeTools]]), `conv.Tools` are wired into the `ChatCompletionRequest.Tools` field and the response's tool calls are normalized via `attackengine.NormalizeOpenAIToolCalls`. This is one of only a few generators with first-class tool support (alongside [[Anthropic]] and [[Google Vertex AI]]).

## Registry name(s)

- `openai.OpenAI` → `NewOpenAI` (`internal/generators/openai/openai.go`)
- `openai.OpenAIReasoning` → `NewOpenAIReasoning` (`internal/generators/openai/reasoning.go`) — for o1/o3 reasoning models

Constructors:
- `NewOpenAI(registry.Config)` — legacy map-based entry point used by the registry
- `NewOpenAITyped(Config)` — type-safe entry point
- `NewOpenAIWithOptions(...Option)` — functional-options entry point (recommended for Go callers)

## Configuration

Parsed by `ConfigFromMap` (`internal/generators/openai/config.go`).

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `model` | string | yes | — | e.g. `gpt-4o`, `gpt-3.5-turbo`, `gpt-3.5-turbo-instruct` |
| `api_key` | string | yes | `OPENAI_API_KEY` env | resolved via `registry.GetAPIKeyWithEnv` |
| `base_url` | string | no | OpenAI default | override for proxies/gateways |
| `temperature` | float | no | 0.7 | only sent if non-zero |
| `max_tokens` | int | no | 0 (unset) | only sent if > 0 |
| `top_p` | float | no | 0 (unset) | |
| `frequency_penalty` | float | no | 0 | |
| `presence_penalty` | float | no | 0 | |
| `stop` | []string | no | nil | stop sequences |

Chat vs. completion model membership is decided by `openaicompat.ChatModels` / `openaicompat.CompletionModels` (shared tables — see [[OpenAI-Compatible]]).

### OpenAIReasoning configuration

Reasoning models (o1/o3) have different constraints, handled by a separate generator (`reasoning.go`, parsed by `ReasoningConfigFromMap`):
- Uses `max_completion_tokens` (default 1500) instead of `max_tokens`.
- Does **not** support `n > 1` (returns an error if multiple generations are requested).
- Does **not** send `temperature`.
- Defaults `top_p` to 1.0 and `stop` to `["#", ";"]`.

## Authentication

API-key bearer auth via the OpenAI SDK. Key comes from the `api_key` config value or the `OPENAI_API_KEY` environment variable. See [[Provider Configuration]].

## Notes

- **Streaming**: not used; responses are read from `resp.Choices` in a single call.
- **Tool-use**: supported on the chat path. `tool_choice` accepts `auto`/`required`/`none` or a specific function name. Tool results in multi-turn conversations are reconstructed by `openaicompat.ConversationToMessages`.
- **Multimodal**: vision-capable model IDs are listed in `ChatModels` but image content is not specially marshalled here.
- **Multiple generations**: chat path passes `N=n` to the API; the legacy completion path also supports `N`.
- **Error handling**: all errors pass through `openaicompat.WrapError("openai", err)`, which maps HTTP 429 to a retryable `*RateLimitError` and classifies 400/401/5xx.
- **Stateless**: `ClearHistory()` is a no-op.

## Source

- `internal/generators/openai/openai.go` — `OpenAI` generator, chat + completion paths, tool wiring
- `internal/generators/openai/config.go` — `Config`, `ConfigFromMap`, functional options
- `internal/generators/openai/reasoning.go` — `OpenAIReasoning` generator
- `internal/generators/openai/reasoning_config.go` — `ReasoningConfig`
- Shared helpers: `internal/generators/openaicompat/openaicompat.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible]]
- [[Anthropic]]
- [[Azure OpenAI]]
- [[Google Vertex AI]]

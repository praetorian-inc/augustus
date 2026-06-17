---
title: OpenAI-Compatible
aliases: ["OpenAI-Compatible Base"]
tags: [augustus, generator, aggregator]
type: reference
component: generator
registry-name: "(shared infrastructure — not directly registered)"
source: internal/generators/openaicompat/openaicompat.go
status: complete
---

# OpenAI-Compatible

> Shared infrastructure package that lets many providers (Groq, Mistral, Together, DeepInfra, Fireworks, Anyscale, NIM, NeMo, LiteLLM, and others) implement the [[Core Interfaces|Generator]] interface with almost no code. It extracts the common OpenAI wire format — message conversion, request building, model tables, and error wrapping — into one place.

## Purpose

The `openaicompat` package is **not a registered generator itself**. Instead it provides:

- `CompatGenerator` — a ready-to-use `Generator` implementation driven by a static `ProviderConfig`.
- `NewGenerator(cfg, ProviderConfig)` — the constructor each compat provider delegates to, eliminating per-provider boilerplate (see [[Together AI]] for the minimal example).
- `ConversationToMessages(conv)` — the canonical `*attempt.Conversation → []goopenai.ChatCompletionMessage` converter, reused by [[OpenAI]], [[Azure OpenAI]], and others. Handles system messages, user/tool roles, and reconstructs prior assistant tool calls.
- `GenerateChat(...)` — standard chat-completion request/response helper covering the common provider case.
- `WrapError(provider, err)` — maps SDK errors to retryable `*RateLimitError` (HTTP 429) and classifies 400/401/5xx.
- `ChatModels` / `CompletionModels` — shared model-name → API-type lookup tables.
- `BaseConfig` — embeddable config struct (`Model`, `APIKey`, `BaseURL`, `Temperature`, `MaxTokens`, `TopP`) with `BaseConfigFromMap`.

## Registry name(s)

None directly. Providers built on this package register their own names, e.g. `together.Together`, `groq.Groq`, `deepinfra.DeepInfra`, `fireworks.Fireworks`, `nim.NIM`, `nemo.NeMo`, `anyscale.Anyscale`, `mistral.Mistral`, `litellm.LiteLLM`.

## Configuration

`NewGenerator` reads these keys from the `registry.Config` map; the `ProviderConfig` supplies provider-specific defaults (name, description, default base URL, API-key env var, default temperature, optional retry config):

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `model` | string | yes | — | provider model name |
| `api_key` | string | yes* | `ProviderConfig.EnvVar` | *or set the provider's env var |
| `base_url` | string | no | `ProviderConfig.DefaultBaseURL` | override gateway/proxy |
| `temperature` | float | no | `ProviderConfig.DefaultTemperature` (else 0.7) | |
| `max_tokens` | int/float | no | unset | |
| `top_p` | float | no | unset | |

## Authentication

API-key bearer auth via the embedded `go-openai` client. Key resolved from `api_key` config or the provider-specific environment variable named in `ProviderConfig.EnvVar`. See [[Provider Configuration]].

## Notes

- **Tool-use**: `CompatGenerator.Generate` calls `GenerateChat`, which does **not** wire `conv.Tools` into the request. Tool-use probes against compat providers will not receive structured tool calls (intentional scope limit; see comments in source re LAB-2981/LAB-2982). For tool support use [[OpenAI]], [[Anthropic]], or [[Google Vertex AI]].
- **Streaming**: not used.
- **Retry**: optional via `ProviderConfig.RetryConfig` (`MaxRetries`, `InitialWait`, `MaxWait`).
- **Rate limiting**: helpers in `ratelimit.go`; 429 responses surface as `*RateLimitError` for retry detection.
- **Stateless**: `ClearHistory()` is a no-op.

## Source

- `internal/generators/openaicompat/openaicompat.go` — `CompatGenerator`, `NewGenerator`, `ConversationToMessages`, `GenerateChat`, `WrapError`, model tables
- `internal/generators/openaicompat/base_config.go` — `BaseConfig`, `BaseConfigFromMap`
- `internal/generators/openaicompat/ratelimit.go` — rate-limit error types
- `internal/generators/openaicompat/README.md` — provider authoring guide

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI]]
- [[Together AI]]
- [[Azure OpenAI]]

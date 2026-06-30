---
title: Anthropic
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "anthropic.Anthropic"
source: internal/generators/anthropic/anthropic.go
status: complete
---

# Anthropic

> Native [[Generators|generator]] for Anthropic's Claude Messages API (Claude 3 / Claude 3.5 — Opus, Sonnet, Haiku), with first-class function-calling (tool-use) support.

## Purpose

Wraps Anthropic's `/v1/messages` endpoint directly over `net/http` (no SDK). It implements the [[Core Interfaces|Generator]] interface, converting an `*attempt.Conversation` into Anthropic's message format and returning `[]attempt.Message`. Unlike OpenAI, it handles Anthropic-specific quirks: the system prompt is a separate top-level parameter, `max_tokens` is mandatory, and there is no `n` parameter (multiple completions are issued as sequential API calls).

## Registry name(s)

- `anthropic.Anthropic` — factory `NewAnthropic`

## Configuration

Parsed by `ConfigFromMap` (`config.go`). See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required** (e.g. `claude-3-5-sonnet-20241022`) |
| `api_key` | string | env fallback | **Required**; falls back to `ANTHROPIC_API_KEY` |
| `base_url` | string | `https://api.anthropic.com/v1` | |
| `api_version` | string | `2023-06-01` | sent as `anthropic-version` header |
| `temperature` | float64 | `0.7` | |
| `max_tokens` | int | `150` | required by API |
| `top_p` | float64 | unset | |
| `top_k` | int | unset | |
| `stop_sequences` | []string | unset | |

HTTP timeout is fixed at 90s. Typed/programmatic construction is available via `NewAnthropicTyped` and `NewAnthropicWithOptions` (functional options like `WithModel`, `WithAPIKey`).

## Authentication

- Header `x-api-key: <api_key>`
- Env var: `ANTHROPIC_API_KEY` (used when `api_key` not in config)

## Notes

- **Tool-use / function-calling**: fully wired. `conv.Tools` are converted to Anthropic `tools` with `input_schema`; `conv.ToolChoice` maps `auto`→`auto`, `required`→`any`, a named tool→`{type:tool, name}`, and `none`→drops tools. Response `tool_use` blocks are normalized via `attackengine.NormalizeAnthropicToolUseBlocks` into `msg.ToolCalls`. Consecutive `RoleTool` turns are coalesced into a single user message of `tool_result` blocks (Anthropic rejects consecutive same-role messages).
- **Streaming**: not used (single buffered response).
- **Multimodal**: text only.
- API keys are masked in `Config.String()` to avoid credential leakage in logs.
- Compare with [[AWS Bedrock]], which can also serve Claude models via AWS.

## Source

`internal/generators/anthropic/anthropic.go`, `internal/generators/anthropic/config.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI]], [[AWS Bedrock]]

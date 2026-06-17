---
title: DeepInfra
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "deepinfra.DeepInfra"
source: internal/generators/deepinfra/deepinfra.go
status: complete
---

# DeepInfra

> [[Generators|Generator]] for DeepInfra's OpenAI-compatible inference API (Llama, Falcon, and other open-source models). Built on the shared [[OpenAI-Compatible Base]].

## Purpose

A thin wrapper over `openaicompat.NewGenerator`. It supplies DeepInfra's defaults; all conversation handling and the chat/completions call are delegated to the shared compat base.

## Registry name(s)

- `deepinfra.DeepInfra` — factory `NewDeepInfra`

## Configuration

Config keys are those of the [[OpenAI-Compatible Base]]. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required** |
| `api_key` | string | env fallback | falls back to `DEEPINFRA_API_KEY` |
| `base_url` | string | `https://api.deepinfra.com/v1/openai` | |
| `temperature` | float32 | base default | |
| `max_tokens` | int | base default | |
| `top_p` | float32 | base default | |

No retry config is set (unlike [[Anyscale]] / [[Groq]]).

## Authentication

- Bearer API key. Env var: `DEEPINFRA_API_KEY`.

## Notes

- **Tool-use**: not wired (compat base limitation).
- **Streaming / multimodal**: not used; text only.
- Functionally identical to [[Fireworks AI]], [[Anyscale]], and [[Groq]] apart from base URL and env var.

## Source

`internal/generators/deepinfra/deepinfra.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI-Compatible Base]], [[Fireworks AI]], [[Anyscale]], [[Groq]]

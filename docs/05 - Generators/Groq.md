---
title: Groq
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "groq.Groq"
source: internal/generators/groq/groq.go
status: complete
---

# Groq

> [[Generators|Generator]] for Groq's fast LPU inference API, exposed through an OpenAI-compatible interface. Built on the shared [[OpenAI-Compatible Base]] with retry support.

## Purpose

A thin wrapper over `openaicompat.NewGenerator`. It supplies Groq's defaults and a retry policy; all conversation handling and the chat/completions call are delegated to the shared compat base.

## Registry name(s)

- `groq.Groq` — factory `NewGroq`

## Configuration

Config keys are those of the [[OpenAI-Compatible Base]]. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required** |
| `api_key` | string | env fallback | falls back to `GROQ_API_KEY` |
| `base_url` | string | `https://api.groq.com/openai/v1` | |
| `temperature` | float32 | base default | |
| `max_tokens` | int | base default | |
| `top_p` | float32 | base default | |

Retry is enabled: 3 retries, 1s initial wait, 30s max wait.

## Authentication

- Bearer API key. Env var: `GROQ_API_KEY`.

## Notes

- **Tool-use**: not wired (compat base limitation).
- **Streaming / multimodal**: not used; text only.
- Functionally identical to [[Anyscale]] (also retry-enabled) and to [[DeepInfra]] / [[Fireworks AI]] (no retry) apart from base URL and env var.

## Source

`internal/generators/groq/groq.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI-Compatible Base]], [[Anyscale]], [[Fireworks AI]], [[DeepInfra]]

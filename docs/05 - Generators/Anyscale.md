---
title: Anyscale
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "anyscale.Anyscale"
source: internal/generators/anyscale/anyscale.go
status: complete
---

# Anyscale

> [[Generators|Generator]] for Anyscale Endpoints, an OpenAI-compatible hosted API serving Llama-2, Mistral, and other open-source models. Built on the shared [[OpenAI-Compatible Base]].

## Purpose

A thin wrapper that delegates all logic to `openaicompat.NewGenerator` (the shared OpenAI-compatible base). It supplies Anyscale's defaults and retry policy; the base handles conversation conversion, the chat/completions call (via the `go-openai` SDK), and error wrapping.

## Registry name(s)

- `anyscale.Anyscale` — factory `NewAnyscale`

## Configuration

Config keys are those of the [[OpenAI-Compatible Base]]. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required** |
| `api_key` | string | env fallback | falls back to `ANYSCALE_API_KEY` |
| `base_url` | string | `https://api.anyscale.com/v1` | |
| `temperature` | float32 | base default | |
| `max_tokens` | int | base default | |
| `top_p` | float32 | base default | |

Retry is enabled: 3 retries, 1s initial wait, 30s max wait.

## Authentication

- Bearer API key. Env var: `ANYSCALE_API_KEY`.

## Notes

- **Tool-use**: not wired — the compat base's `GenerateChat` does not forward `conv.Tools` (see [[OpenAI-Compatible Base]]).
- **Streaming / multimodal**: not used; text only.
- Behavior is identical to other compat providers ([[DeepInfra]], [[Fireworks AI]], [[Groq]]) apart from defaults.
- A `anyscale.go.backup` file exists in the package but is not compiled.

## Source

`internal/generators/anyscale/anyscale.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI-Compatible Base]], [[Groq]], [[Fireworks AI]], [[DeepInfra]]

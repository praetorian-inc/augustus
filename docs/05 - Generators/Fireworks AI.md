---
title: Fireworks AI
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "fireworks.Fireworks"
source: internal/generators/fireworks/fireworks.go
status: complete
---

# Fireworks AI

> [[Generators|Generator]] for Fireworks AI's fast OpenAI-compatible inference API serving various open-source models. Built on the shared [[OpenAI-Compatible Base]].

## Purpose

A thin wrapper over `openaicompat.NewGenerator`. It provides only Fireworks-specific defaults; the shared compat base does the rest.

## Registry name(s)

- `fireworks.Fireworks` — factory `NewFireworks`

## Configuration

Config keys are those of the [[OpenAI-Compatible Base]]. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required** |
| `api_key` | string | env fallback | falls back to `FIREWORKS_API_KEY` |
| `base_url` | string | `https://api.fireworks.ai/inference/v1` | |
| `temperature` | float32 | base default | |
| `max_tokens` | int | base default | |
| `top_p` | float32 | base default | |

No retry config is set.

## Authentication

- Bearer API key. Env var: `FIREWORKS_API_KEY`.

## Notes

- **Tool-use**: not wired (compat base limitation).
- **Streaming / multimodal**: not used; text only.
- Functionally identical to [[DeepInfra]], [[Anyscale]], and [[Groq]] apart from base URL and env var.

## Source

`internal/generators/fireworks/fireworks.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI-Compatible Base]], [[DeepInfra]], [[Groq]], [[Anyscale]]

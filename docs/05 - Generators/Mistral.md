---
title: Mistral
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "mistral.Mistral"
source: internal/generators/mistral/mistral.go
status: complete
---

# Mistral

> Generator for the [Mistral AI](https://mistral.ai/) chat completions API, built on the shared OpenAI-compatible generator.

## Purpose

Probes Mistral's hosted models (e.g. Mistral-7B, Mixtral-8x7B) via their OpenAI-compatible chat endpoint. Implemented as a thin wrapper over [[OpenAI-Compatible Base]] (`openaicompat.NewGenerator`).

## Registry name(s)

- `mistral.Mistral`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | Mistral model name. |
| `api_key` | yes | API key; env `MISTRAL_API_KEY`. |
| `base_url` | no | Default `https://api.mistral.ai/v1`. |
| `temperature` | no | Default 0.7. |
| `max_tokens` / `top_p` | no | Standard sampling params. |

## Authentication

API key via `api_key` config or env `MISTRAL_API_KEY` (required — `GetAPIKeyWithEnv`).

## Notes

- OpenAI-compatible chat completions through the shared compat generator.
- Inherits compat-layer behavior for `n`, error wrapping, and rate limiting.
- No streaming or native tool-use exposed here; not multimodal.
- Stateless per call.

## Source

- `internal/generators/mistral/mistral.go`
- `internal/generators/mistral/config.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible Base]]

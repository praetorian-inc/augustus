---
title: NVIDIA NeMo
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "nemo.NeMo"
source: internal/generators/nemo/nemo.go
status: complete
---

# NVIDIA NeMo

> Generator for NVIDIA NeMo models hosted on NGC, exposed through an OpenAI-compatible API.

## Purpose

Probes models served by NVIDIA NeMo on NGC (NVIDIA GPU Cloud) via their OpenAI-compatible endpoint. Built on the shared [[OpenAI-Compatible Base]] generator. Not to be confused with [[NeMo Guardrails]] (`guardrails.NeMoGuardrails`), which targets the guardrails server rather than a model.

## Registry name(s)

- `nemo.NeMo`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | NeMo/NGC model name. |
| `api_key` | yes | API key; env `NGC_API_KEY`. |
| `base_url` | no | Default `https://api.llm.ngc.nvidia.com/v1`. |
| `temperature` | no | Default 0.9 (provider override). |
| `max_tokens` / `top_p` | no | Standard sampling params. |

## Authentication

NGC API key via `api_key` config or env `NGC_API_KEY`.

## Notes

- OpenAI-compatible chat completions via `openaicompat.NewGenerator`.
- Default temperature is 0.9 (set by the `ProviderConfig`).
- Config embeds `openaicompat.BaseConfig`.
- No streaming or native tool-use exposed here; not multimodal. Stateless per call.

## Source

- `internal/generators/nemo/nemo.go`
- `internal/generators/nemo/config.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible Base]]
- [[NeMo Guardrails]]
- [[NVIDIA NIM]]
- [[NVIDIA Cloud Functions]]

---
title: NVIDIA NIM
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "nim.NIM"
source: internal/generators/nim/nim.go
status: complete
---

# NVIDIA NIM

> Generators for NVIDIA NIM (Inference Microservices), the OpenAI-compatible serving layer for models such as LLaMA-2 and Mixtral. Four variants cover chat, text completion, and multimodal/vision inputs.

## Purpose

Probes models served through NVIDIA NIM, reachable at the hosted `https://integrate.api.nvidia.com/v1` endpoint or any self-hosted NIM microservice (via `base_url`). The chat variant builds on the shared [[OpenAI-Compatible Base]]; the completion/multimodal/vision variants use a dedicated go-openai client.

## Registry name(s)

- `nim.NIM` — chat completions (compat generator).
- `nim.NVOpenAICompletion` — legacy `v1/completions` text endpoint (default temp 0.7).
- `nim.NVMultimodal` — chat completions for text/image/audio inputs (default temp 0.1).
- `nim.Vision` — thin wrapper over `NVMultimodal` for text + image.

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | NIM model name. |
| `api_key` | yes | API key; env `NIM_API_KEY`. |
| `base_url` | no | Default `https://integrate.api.nvidia.com/v1`; set for self-hosted NIM. |
| `temperature` | no | Defaults: NIM uses compat default; completion 0.7; multimodal/vision 0.1. |
| `max_tokens` / `top_p` | no | Standard sampling params. |

All variants share `Config` (embeds `openaicompat.BaseConfig`) and build a go-openai client pointed at `base_url`.

## Authentication

API key via `api_key` config or env `NIM_API_KEY`.

## Notes

- `nim.NIM` is OpenAI-compatible chat; inherits compat-layer `n`, error wrapping, rate limiting.
- `nim.NVOpenAICompletion` flattens the conversation into a single prompt string and calls the completions endpoint with native `n`.
- `nim.NVMultimodal` / `nim.Vision` use chat completions with native `n`; multimodal intended for text + image (+ audio) inputs.
- No streaming exposed; no native function-calling tool-use. Stateless per call.

## Source

- `internal/generators/nim/nim.go`
- `internal/generators/nim/config.go`
- `internal/generators/nim/completion.go`
- `internal/generators/nim/multimodal.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible Base]]
- [[NVIDIA NeMo]]
- [[NVIDIA Cloud Functions]]

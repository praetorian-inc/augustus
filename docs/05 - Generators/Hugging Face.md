---
title: Hugging Face
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "huggingface.InferenceAPI"
source: internal/generators/huggingface/inference.go
status: complete
---

# Hugging Face

> Four generators wrapping Hugging Face inference surfaces: the hosted Inference API, custom Inference Endpoints, local Text Generation Inference (TGI) pipelines, and LLaVA vision-language models.

## Purpose

Lets Augustus probe models served by Hugging Face, whether hosted on the public Inference API, behind a dedicated Inference Endpoint, run locally via TGI, or a multimodal LLaVA model. Spans cloud-api and local deployment modes under one provider namespace.

## Registry name(s)

- `huggingface.InferenceAPI` — hosted Inference API (`https://api-inference.huggingface.co/models/{model}`).
- `huggingface.InferenceEndpoint` — POSTs directly to a custom endpoint URL (no model suffix).
- `huggingface.Pipeline` — local TGI server, OpenAI-compatible `/v1/chat/completions`.
- `huggingface.LLaVA` — hosted vision-language model (text input today; image support stubbed).

## Configuration

### `huggingface.InferenceAPI` / `huggingface.LLaVA`

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | Model id (e.g. `meta-llama/Llama-2-7b-chat-hf`). |
| `api_key` | no | Token; falls back to env vars (see Authentication). |
| `base_url` | no | Override (default `https://api-inference.huggingface.co/models`). |
| `max_tokens` | no | Maps to `max_new_tokens`. |
| `max_time` | no | Max generation seconds (default 20). |
| `deprefix_prompt` | no | InferenceAPI only; controls `return_full_text`. Default true. |
| `wait_for_model` | no | Wait for cold model load. Default false. |

### `huggingface.InferenceEndpoint`

| Key | Required | Description |
|-----|----------|-------------|
| `endpoint_url` | yes | Full custom endpoint URL. |
| `api_key` | no | Bearer token. |
| `max_tokens` | no | Maps to `max_new_tokens`. |

### `huggingface.Pipeline` (local TGI)

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | Model id served by TGI. |
| `host` | no | TGI address (default `http://127.0.0.1:8080`, env `TGI_HOST`). |
| `max_tokens` / `temperature` / `top_p` | no | Generation params. |
| `deprefix_prompt` | no | Default true. |

## Authentication

InferenceAPI / LLaVA: `api_key` or, if absent, env `HF_INFERENCE_TOKEN` then `HUGGINGFACE_API_KEY`, sent as a bearer token. InferenceEndpoint: optional `api_key` bearer token. Pipeline: no auth (local).

## Notes

- Hosted API and LLaVA retry up to 3 times on HTTP 503 (model loading), flipping `wait_for_model` on; 429 surfaces a rate-limit error.
- `n > 1` is requested via `num_return_sequences` (+ `do_sample`); InferenceEndpoint ignores `n` (single generation per request).
- Pipeline uses the OpenAI-compatible chat schema and passes `n` directly.
- LLaVA is multimodal in intent but currently sends only the text prompt (image support pending).
- No streaming; no native tool-use.
- All variants are stateless (`ClearHistory` no-op).

## Source

- `internal/generators/huggingface/inference.go`
- `internal/generators/huggingface/inferenceendpoint.go`
- `internal/generators/huggingface/pipeline.go`
- `internal/generators/huggingface/llava.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Ollama]]

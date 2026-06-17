---
title: NVIDIA Cloud Functions
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "nvcf.NvcfChat"
source: internal/generators/nvcf/nvcf.go
status: complete
---

# NVIDIA Cloud Functions

> Generators for NVIDIA Cloud Functions (NVCF), invoking a deployed function by ID in either chat or text-completion mode.

## Purpose

Probes models deployed as NVIDIA Cloud Functions. Each call POSTs to `{base_url}/{function_id}`. Two registrations cover chat (`messages` payload) and completion (`prompt` payload); the completion variant embeds the chat variant and shares its config and HTTP plumbing.

## Registry name(s)

- `nvcf.NvcfChat` — chat completion (sends `messages`, reads `choices[].message.content`).
- `nvcf.NvcfCompletion` — text completion (sends last-turn `prompt`, reads `choices[].text`).

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `function_id` | yes | NVCF function ID; appended to the base URL. |
| `api_key` | yes | API key; env `NVCF_API_KEY`. |
| `base_url` | no | Default `https://api.nvcf.nvidia.com/v2/nvcf/pexec/functions`. |
| `model` | no | Optional model field added to the payload. |
| `temperature` | no | Default 0.7. |
| `max_tokens` / `top_p` | no | Standard sampling params. |

## Authentication

Bearer token: `api_key` config or env `NVCF_API_KEY` (required).

## Notes

- `stream` is always set to `false`; no streaming support.
- No native tool-use; not multimodal.
- `n` is accepted but the payload requests a single generation; multiple choices in the response are all returned.
- Non-2xx responses surface the status code and body. Stateless (`ClearHistory` no-op).

## Source

`internal/generators/nvcf/nvcf.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[NVIDIA NIM]]
- [[NVIDIA NeMo]]

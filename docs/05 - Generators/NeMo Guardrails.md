---
title: NeMo Guardrails
tags: [augustus, generator, framework]
type: reference
component: generator
registry-name: "guardrails.NeMoGuardrails"
source: internal/generators/guardrails/nemoguardrails.go
status: complete
---

# NeMo Guardrails

> Generator that wraps an [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) server, letting Augustus probe an LLM application *through* its programmable guardrails (input/output rails, dialog rails, fact-checking) rather than the raw model.

## Purpose

NeMo Guardrails is a toolkit for adding programmable guardrails to LLM-based conversational systems. This generator targets the guardrails HTTP server so adversarial prompts are evaluated against the rails configuration in place — useful for testing whether guardrails can be bypassed. It is distinct from [[NVIDIA NeMo]] (`nemo.NeMo`), which talks to NGC-hosted models directly.

## Registry name(s)

- `guardrails.NeMoGuardrails`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `rails_config` | yes | Config id / name of the rails configuration to apply (sent as `config_id`). |
| `base_url` | yes | HTTP endpoint of the NeMo Guardrails server (trailing slash trimmed). |
| `api_key` | no | Bearer token for the server. |

Requests are POSTed to `{base_url}/v1/chat/completions` with `{config_id, messages}`.

## Authentication

Optional. If `api_key` is set, an `Authorization: Bearer <key>` header is added. No environment-variable fallback.

## Notes

- No streaming; `stream` is not requested.
- No tool-use or multimodal support.
- `n > 1` is emulated with sequential calls (the API returns one response per call).
- Response content is the last `assistant` message in the returned `messages` array.
- `ClearHistory` is a no-op (stateless per call).
- Error handling maps 400/401/429/5xx to descriptive errors.

## Source

`internal/generators/guardrails/nemoguardrails.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[NVIDIA NeMo]]
- [[NVIDIA NIM]]

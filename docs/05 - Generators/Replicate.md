---
title: Replicate
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "replicate.Replicate"
source: internal/generators/replicate/replicate.go
status: complete
---

# Replicate

> Generator for [Replicate](https://replicate.com/), the model-hosting platform for running open-source models (Llama, Mistral, etc.). Models are addressed as `owner/model-name` or `owner/model-name:version`, and both public models and private deployments are supported.

## Purpose

`Replicate` implements the [[Core Interfaces|Generator]] interface on top of the `github.com/replicate/replicate-go` SDK. It sends the conversation's last prompt as the model's `prompt` input along with sampling parameters, then normalizes the prediction output (which may be a string, `[]string`, or `[]any`) into assistant text.

## Registry name(s)

- `replicate.Replicate` → `NewReplicate` (`internal/generators/replicate/replicate.go`)

Constructors:
- `NewReplicate(registry.Config)` — map-based registry entry point
- `NewReplicateTyped(Config)` — type-safe entry point
- `NewReplicateWithOptions(...Option)` — functional-options entry point

## Configuration

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `model` | string | yes | — | `owner/model-name[:version]` |
| `api_key` | string | yes | `REPLICATE_API_TOKEN` env | API token |
| `temperature` | float | no | 1.0 | sent as `temperature` |
| `top_p` | float | no | 1.0 | nucleus sampling |
| `repetition_penalty` | float | no | 1.0 | |
| `max_tokens` | int | no | model-specific | sent to the model as `max_length` when > 0 |
| `seed` | int | no | 9 | reproducibility |
| `base_url` | string | no | Replicate default | custom endpoint for testing/proxies |

## Authentication

API-token auth via the Replicate SDK (`WithToken`). Token from `api_key` config or the `REPLICATE_API_TOKEN` environment variable. See [[Provider Configuration]].

## Notes

- **Multiple generations**: Replicate has no batch generation, so `Generate` loops `n` times, one prediction per iteration.
- **Output handling**: `extractText` joins streamed string chunks (`[]string`/`[]any`) into a single response; non-string outputs fall back to `%v` formatting.
- **Error handling**: `wrapError` adds context, surfacing `*replicatego.APIError` status codes.
- **Empty prompt**: returns an error if the conversation has no prompt.
- **Streaming / tool-use / multimodal**: not supported in this integration.
- **Stateless**: `ClearHistory()` is a no-op.

## Source

- `internal/generators/replicate/replicate.go` — `Replicate` generator, output extraction, error wrapping

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Hugging Face]]
- [[Ollama]]

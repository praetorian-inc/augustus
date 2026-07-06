---
title: Azure OpenAI
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "azure.AzureOpenAI"
source: internal/generators/azure/azure.go
status: complete
---

# Azure OpenAI

> [[Generators|Generator]] for Azure OpenAI Service — GPT models hosted on a customer's Azure resource, supporting both chat and legacy completion APIs.

## Purpose

Implements the [[Core Interfaces|Generator]] interface against Azure OpenAI using the `go-openai` SDK configured via `DefaultAzureConfig`. It reuses the [[OpenAI-Compatible Base]] helpers (`ConversationToMessages`, `WrapError`, and the shared `ChatModels`/`CompletionModels` sets) to decide whether to call the chat or legacy completion endpoint, and maps Azure deployment names to OpenAI model equivalents.

## Registry name(s)

- `azure.AzureOpenAI` — factory `NewAzure`

## Configuration

Parsed by `ConfigFromMap` (`config.go`). Three values are required. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | env `AZURE_MODEL_NAME` | **Required**; Azure deployment/model name |
| `api_key` | string | env `AZURE_API_KEY` | **Required** |
| `endpoint` | string | env `AZURE_ENDPOINT` | **Required**; e.g. `https://your-resource.openai.azure.com` |
| `api_version` | string | `2024-06-01` | |
| `temperature` | float32 | unset | |
| `max_tokens` | int | unset | |
| `top_p` | float32 | unset | |
| `frequency_penalty` | float32 | unset | |
| `presence_penalty` | float32 | unset | |
| `stop` | []string | unset | |

Azure model names are remapped to OpenAI equivalents (e.g. `gpt-4`→`gpt-4-turbo-2024-04-09`, `gpt-35-turbo`→`gpt-3.5-turbo-0125`). Chat vs completion routing comes from the shared model sets; unknown models default to chat.

## Authentication

- Azure API key via `DefaultAzureConfig(apiKey, endpoint)`.
- Env vars: `AZURE_API_KEY`, `AZURE_ENDPOINT`, `AZURE_MODEL_NAME`.

## Notes

- Supports both **chat** (`generateChat`) and **legacy completion** (`generateCompletion`) flows; honors `n` for multiple completions.
- **Tool-use / streaming / multimodal**: not wired; text only.
- Distinct from plain [[OpenAI]] by requiring a resource `endpoint` and `api_version`.
- API key masked in `Config.String()`.

## Source

`internal/generators/azure/azure.go`, `internal/generators/azure/config.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[OpenAI]], [[OpenAI-Compatible Base]]

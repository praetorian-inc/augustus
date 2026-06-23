---
title: Google Vertex AI
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "vertex.Vertex"
source: internal/generators/vertex/vertex.go
status: complete
---

# Google Vertex AI

> Generator for Google Cloud's Vertex AI `generateContent` API, supporting Gemini models (gemini-pro, gemini-pro-vision) and PaLM 2 (text-bison, chat-bison). One of the few generators with full tool-use / function-calling support, using Gemini's native `functionDeclarations` and `functionCall`/`functionResponse` content parts.

## Purpose

`Vertex` implements the [[Core Interfaces|Generator]] interface against the raw Vertex AI REST API (no SDK). It differs from OpenAI-style providers in three notable ways: messages go in a `contents` array (not `messages`), system prompts are sent via a separate `systemInstruction` field (never inside `contents`), and generation parameters live in a `generationConfig` object.

## Registry name(s)

- `vertex.Vertex` → `NewVertex` (`internal/generators/vertex/vertex.go`)

Constructors:
- `NewVertex(registry.Config)` — map-based registry entry point
- `NewVertexTyped(Config)` — type-safe entry point
- `NewVertexWithOptions(...Option)` — functional-options entry point

## Configuration

Parsed by `ConfigFromMap` (`internal/generators/vertex/config.go`).

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `model` | string | yes | — | e.g. `gemini-pro` |
| `project_id` | string | yes | — | GCP project ID |
| `location` | string | no | `us-central1` | region; used to build the default base URL |
| `api_key` | string | no | `GOOGLE_API_KEY` env | sent as `Authorization: Bearer` if present |
| `base_url` | string | no | `https://{location}-aiplatform.googleapis.com/v1` | override |
| `temperature` | float | no | 0.7 | |
| `max_output_tokens` | int | no | 150 | |
| `top_p` | float | no | unset | |
| `top_k` | int | no | unset | |
| `stop_sequences` | []string | no | nil | |

Endpoint URL: `{base}/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent`.

## Authentication

Bearer-token auth: if `api_key` (or `GOOGLE_API_KEY`) is set, it is sent as `Authorization: Bearer <key>`. For production, Application Default Credentials (ADC) are the documented path. See [[Provider Configuration]].

## Notes

- **Tool-use**: fully supported. `conv.Tools` map to Gemini `functionDeclarations`; `tool_choice` maps to `functionCallingConfig` modes — `auto`→`AUTO`, `required`→`ANY`, `none`→`NONE` (tools removed), or a specific name → `ANY` with `allowedFunctionNames`. Responses' `functionCall` parts are normalized via `attackengine.NormalizeGeminiFunctionCalls`. Tool results in multi-turn use the `function` role with a `functionResponse` part keyed by **function name** (Gemini matches by name, not call ID — `ToolCallID` carries the name).
- **System prompt**: passed as `systemInstruction`, excluded from `contents`.
- **Multiple generations**: no batch support — `Generate` loops `n` times.
- **Streaming / multimodal**: vision model IDs are supported by the API but image content is not specially marshalled here.
- **Error handling**: `handleError` classifies 429/400/401/403/5xx from the structured `error` object.
- **Stateless**: `ClearHistory()` is a no-op.

## Source

- `internal/generators/vertex/vertex.go` — `Vertex` generator, contents conversion, tool wiring, error handling
- `internal/generators/vertex/config.go` — `Config`, `ConfigFromMap`, options

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI]]
- [[Anthropic]]
- [[Bedrock]]

---
title: Rasa
tags: [augustus, generator, framework]
type: reference
component: generator
registry-name: "rasa.RasaRest"
source: internal/generators/rasa/rasa.go
status: complete
---

# Rasa

> Generator for chatbots built on the [Rasa](https://rasa.com/) open-source conversational-AI framework. Talks to Rasa's REST channel at `/webhooks/rest/webhook` using its simple `{sender, message}` request and `[{text}]` response format.

## Purpose

`RasaRest` implements the [[Core Interfaces|Generator]] interface for Rasa assistants. Unlike the generic [[REST]] generator it hard-codes the Rasa REST webhook contract, so no request/response templating is needed. It posts the conversation's last prompt as a single message and returns every text reply Rasa emits (Rasa may return an array of bot messages).

## Registry name(s)

- `rasa.RasaRest` → `NewRasaRest` (`internal/generators/rasa/rasa.go`)

Constructors:
- `NewRasaRest(registry.Config)` — map-based registry entry point
- `NewRasaRestTyped(Config)` — type-safe entry point

## Configuration

All three keys are required (`Config`: `BaseURL`, `Model`, `Sender`):

| Key | Type | Required | Notes |
|-----|------|----------|-------|
| `base_url` | string | yes | Rasa server base URL; `/webhooks/rest/webhook` is appended |
| `model` | string | yes | model/assistant identifier (metadata) |
| `sender` | string | yes | Rasa conversation/sender ID |

HTTP client timeout is fixed at 30s.

## Authentication

None built in. If the Rasa endpoint requires auth, front it with a proxy or use the generic [[REST]] generator with custom headers instead.

## Notes

- **Request format**: `POST {base_url}/webhooks/rest/webhook` with body `{"sender": ..., "message": <last prompt>}`.
- **Response format**: expects a JSON array of `{"text": ...}` objects; each becomes an assistant message.
- **Multiple generations**: the `n` parameter is ignored — Rasa returns whatever bot turns it produces for the single message.
- **Error handling**: any non-200 status returns an error including the response body.
- **Streaming / tool-use / multimodal**: not supported.
- **Stateless**: `ClearHistory()` is a no-op (conversation state lives server-side, keyed by `sender`).

## Source

- `internal/generators/rasa/rasa.go` — `RasaRest` generator, request/response structs

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[REST]]
- [[LangChain]]

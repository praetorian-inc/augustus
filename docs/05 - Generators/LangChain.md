---
title: LangChain
tags: [augustus, generator, framework]
type: reference
component: generator
registry-name: "langchain.LangChain"
source: internal/generators/langchain/langchain.go
status: complete
---

# LangChain

> Generator that wraps a LangChain runnable exposed over HTTP, calling its `invoke()`-style REST endpoint.

## Purpose

Targets LangChain LLM interfaces served via an HTTP `invoke` endpoint (typically through LangServe). Lets Augustus probe a LangChain chain/runnable end-to-end rather than the underlying model. For the dedicated LangServe application convention (`/invoke`, `config_hash`, output array), see [[LangChain Serve]].

## Registry name(s)

- `langchain.LangChain`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `uri` | yes | Full URL of the LangChain invoke endpoint (validated with `url.Parse`). |

HTTP client uses a fixed 30s timeout. Single-turn requests send `{"input": "<prompt>"}`; multi-turn or system-prefixed conversations send `{"input": [...messages...]}`.

## Authentication

None built in. Auth must be embedded in the URL or handled by the endpoint itself.

## Notes

- No streaming; no native tool-use; no multimodal.
- `invoke()` does not support `n > 1` — exactly one call is made regardless of `n`.
- Response must contain a top-level `content` string field, else an error is returned.
- Stateless (`ClearHistory` no-op).

## Source

`internal/generators/langchain/langchain.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[LangChain Serve]]
- [[REST]]

---
title: LangChain Serve
tags: [augustus, generator, framework]
type: reference
component: generator
registry-name: "langchain_serve.LangChainServe"
source: internal/generators/langchainserve/langchainserve.go
status: complete
---

# LangChain Serve

> Generator that wraps a [LangServe](https://github.com/langchain-ai/langserve) application, POSTing to its `/invoke` endpoint with the LangServe request envelope.

## Purpose

Targets LangServe-deployed LangChain applications, which expose a conventional `/invoke` endpoint and return an `output` array. Distinct from the more generic [[LangChain]] generator: it appends `/invoke` to a base URL, supports a `config_hash` query parameter, custom headers, and reads the LangServe-shaped response.

## Registry name(s)

- `langchain_serve.LangChainServe`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `base_url` | yes | Base URL of the LangServe app; `/invoke` is appended (validated with `url.Parse`). |
| `config_hash` | no | Added as a `config_hash` query parameter on the invoke URL. |
| `headers` | no | Map of custom request headers (string values). |
| `timeout` | no | Request timeout in seconds (default 30). |

Request body is `{"input": "<prompt>", "config": {}, "kwargs": {}}`.

## Authentication

None built in; supply credentials via the `headers` map (e.g. an `Authorization` header).

## Notes

- No streaming; no native tool-use; no multimodal.
- `/invoke` does not support `n > 1` — one call regardless of `n`.
- Response is expected as `{"output": ["<text>", ...]}`; the first element is used.
- Stateless (`ClearHistory` no-op).

## Source

`internal/generators/langchainserve/langchainserve.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[LangChain]]
- [[REST]]

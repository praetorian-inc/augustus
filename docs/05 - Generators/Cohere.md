---
title: Cohere
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "cohere.Cohere"
source: internal/generators/cohere/cohere.go
status: complete
---

# Cohere

> [[Generators|Generator]] for Cohere's Chat (v2) and legacy Generate (v1) APIs, defaulting to the recommended v2 chat endpoint.

## Purpose

Implements the [[Core Interfaces|Generator]] interface directly over `net/http`. Following Cohere's migration guide, it can target either API version: `v2` uses `/v2/chat` (default, recommended) and `v1` uses `/v1/generate` (legacy, supports `num_generations` up to 5 per call).

## Registry name(s)

- `cohere.Cohere` — factory `NewCohere`

## Configuration

Parsed by `ConfigFromMap` (`config.go`). See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `api_key` | string | env fallback | **Required**; falls back to `COHERE_API_KEY` |
| `model` | string | `command` | |
| `base_url` | string | `https://api.cohere.com` | |
| `api_version` | string | `v2` | only `v1` or `v2` accepted |
| `temperature` | float64 | `0.75` | |
| `max_tokens` | int | unset | |
| `k` | int | unset | top-k |
| `p` | float64 | `0.75` | top-p |
| `frequency_penalty` | float64 | unset | |
| `presence_penalty` | float64 | unset | |
| `stop` | []string | unset | |

Note the Cohere-specific key names: `k` (top-k) and `p` (top-p).

## Authentication

- Bearer API key. Env var: `COHERE_API_KEY`.

## Notes

- **Dual API**: v2 chat (default) vs v1 generate (legacy); v1 caps generations at 5 per request.
- Imports `attackengine`, so tool-call normalization helpers are available, but Cohere is primarily a text generator here.
- **Streaming / multimodal**: not used; text only.
- API key masked in logs.

## Source

`internal/generators/cohere/cohere.go`, `internal/generators/cohere/config.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]]

---
title: Ollama
tags: [augustus, generator, local]
type: reference
component: generator
registry-name: "ollama.Ollama"
source: internal/generators/ollama/ollama.go
status: complete
---

# Ollama

> Generators for a local [Ollama](https://ollama.com/) instance, exposing both the text-completion (`/api/generate`) and multi-turn chat (`/api/chat`) endpoints.

## Purpose

Probes models running locally via Ollama — ideal for privacy-sensitive testing (no data leaves the machine), cost-free runs, and offline development. Model names accept short forms (`llama2`) or tagged versions (`gemma:7b`, `llama2:latest`).

## Registry name(s)

- `ollama.Ollama` — `/api/generate`, text completion from the last prompt.
- `ollama.OllamaChat` — `/api/chat`, full multi-turn conversation.

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `model` | yes | Ollama model name/tag. |
| `host` | no | Server URL; env `OLLAMA_HOST`; default `http://127.0.0.1:11434` (trailing slash trimmed). |
| `timeout` | no | Request timeout in seconds (default 30). |
| `temperature` / `top_p` / `top_k` / `num_predict` | no | Generation options (pointer-typed to distinguish unset from zero). |

## Authentication

None — local server, no API key.

## Notes

- `stream` is always `false`; responses are read whole.
- Ollama does not support an `n` parameter — `n > 1` is emulated with sequential calls.
- No native tool-use exposed; not multimodal.
- Both generators share a `baseConfig`; options are only attached to the request when at least one is set.
- Stateless (`ClearHistory` no-op). Typed constructors (`NewOllamaTyped`, `NewOllamaWithOptions`) exist for programmatic use.

## Source

- `internal/generators/ollama/ollama.go`
- `internal/generators/ollama/config.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Hugging Face]]

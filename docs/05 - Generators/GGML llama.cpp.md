---
title: GGML / llama.cpp
tags: [augustus, generator, local]
type: reference
component: generator
registry-name: "ggml.Ggml"
source: internal/generators/ggml/ggml.go
status: complete
---

# GGML / llama.cpp

> Local [[Generators|generator]] that runs inference by shelling out to a llama.cpp / GGML executable against a local GGUF model file — no network, no API key.

## Purpose

Implements the [[Core Interfaces|Generator]] interface by invoking a local GGML/llama.cpp binary via `exec.CommandContext`. The prompt and sampling parameters are passed as CLI flags and the model's stdout is captured as the response. This makes it suitable for offline testing of locally hosted models.

## Registry name(s)

- `ggml.Ggml` — factory `NewGgml`

## Configuration

Parsed by `ConfigFromMap` (`config.go`). See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required**; path to the `.gguf` model file |
| `ggml_main_path` | string | env `GGML_MAIN_PATH` | **Required**; path to the llama.cpp executable |
| `temperature` | float64 | `0.8` | → `--temp` |
| `top_k` | int | `40` | → `--top-k` |
| `top_p` | float64 | `0.95` | → `--top-p` |
| `max_tokens` | int | unset | → `-n` |
| `repeat_penalty` | float64 | `1.1` | → `--repeat-penalty` |
| `extra_ggml_flags` | []string | unset | appended verbatim to the command line |

`Validate()` requires both the model path and the executable path.

## Authentication

- None. This is a local process; no credentials or env-based API keys (only `GGML_MAIN_PATH` to locate the binary).

## Notes

- **Execution model**: spawns the binary per generation with built CLI args (`--temp`, `--top-k`, `--top-p`, `-n`, `--repeat-penalty`, plus any `extra_ggml_flags`).
- **Tool-use / streaming / multimodal**: not supported.
- Compare with [[Ollama]] for an HTTP-based local server alternative.

## Source

`internal/generators/ggml/ggml.go`, `internal/generators/ggml/config.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[Ollama]]

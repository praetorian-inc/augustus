---
title: LiteLLM
tags: [augustus, generator, aggregator]
type: reference
component: generator
registry-name: "litellm.LiteLLM"
source: internal/generators/litellm/litellm.go
status: complete
---

# LiteLLM

> Generator that connects to a [LiteLLM](https://github.com/BerriAI/litellm) proxy server, giving Augustus OpenAI-compatible access to 100+ underlying LLM providers (OpenAI, Anthropic, Azure, Bedrock, Cohere, Replicate, …) through one endpoint.

## Purpose

LiteLLM is a unified LLM gateway. This generator points a [go-openai](https://github.com/sashabaranov/go-openai) client at a running LiteLLM proxy, so any model the proxy routes to can be probed with a single Augustus configuration. Start a proxy with `litellm --model gpt-4o --port 4000` (or a `config.yaml` for multi-model routing).

## Registry name(s)

- `litellm.LiteLLM`

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `proxy_url` (alias `api_base`) | yes | LiteLLM proxy URL (e.g. `http://localhost:4000`); normalized to end in `/v1`. |
| `model` | yes | Model name with provider prefix (e.g. `anthropic/claude-3-opus`). |
| `api_key` | no | Proxy key; env `LITELLM_API_KEY`; defaults to placeholder `"anything"` when keys are server-side. |
| `temperature` | no | Default 0.7. |
| `max_tokens` / `top_p` / `frequency_penalty` / `presence_penalty` / `stop` | no | Standard sampling params. |
| `suppressed_params` | no | List of params to omit for providers that reject them. |

## Authentication

Bearer key via `api_key` or env `LITELLM_API_KEY`. Falls back to the literal `"anything"` since LiteLLM proxies often hold provider keys server-side.

## Notes

- OpenAI-compatible chat completions; uses a pooled HTTP client (120s timeout, 100 idle conns).
- `n > 1`: uses the native `n` parameter when supported, but falls back to sequential calls for model prefixes in `unsupportedMultipleGenProviders` (`claude`, `anthropic/`, `bedrock`, `replicate/`, `together_ai/`, `palm/`, bison models, `openrouter/`, `petals`).
- `suppressed_params` lets you drop unsupported fields (incl. `n`) per backend.
- Errors are wrapped via the shared [[OpenAI-Compatible Base]] `WrapError`.
- No streaming; no native tool-use exposed here. Stateless (`ClearHistory` no-op).

## Source

- `internal/generators/litellm/litellm.go`
- `internal/generators/litellm/config.go`

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[OpenAI-Compatible Base]]

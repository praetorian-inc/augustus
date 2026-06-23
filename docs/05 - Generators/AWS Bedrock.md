---
title: AWS Bedrock
aliases: ["Bedrock"]
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "bedrock.Bedrock"
source: internal/generators/bedrock/bedrock.go
status: complete
---

# AWS Bedrock

> [[Generators|Generator]] for AWS Bedrock's `InvokeModel` runtime, fronting multiple model families (Claude/Anthropic, Titan/Amazon, Llama/Meta) through a single AWS-authenticated interface.

## Purpose

Implements the [[Core Interfaces|Generator]] interface using AWS SDK v2 (`bedrockruntime`). Each model family has a distinct request/response JSON body, so the generator detects the family from the model ID and formats payloads accordingly. Bedrock does not support multiple completions per call, so `n>1` is satisfied with sequential `InvokeModel` calls.

## Registry name(s)

- `bedrock.Bedrock` — factory `NewBedrock`

## Configuration

Parsed inline in `NewBedrock` / typed in `config.go`. See [[Provider Configuration]].

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `model` | string | — | **Required**; Bedrock model ID (e.g. `anthropic.claude-3-sonnet-...`) |
| `region` | string | — | **Required**; AWS region |
| `max_tokens` | int | `150` | |
| `temperature` | float64 | `0.7` | |
| `top_p` | float64 | unset | |
| `endpoint` | string | unset | custom base endpoint (testing) |

## Authentication

- Uses the **AWS default credential chain** via `config.LoadDefaultConfig` (env vars `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, shared `~/.aws/credentials`, IAM roles, etc.) scoped to the configured `region`.
- No API key configuration — credentials are entirely AWS-side.

## Notes

- **Multi-model**: handles Claude, Amazon Titan, and Meta Llama families with per-family payload shaping.
- A custom `endpoint` and (in tests) a custom HTTP client can override the SDK defaults.
- **Tool-use / streaming / multimodal**: not wired in this generator; text only.
- For Claude specifically, [[Anthropic]] is the native alternative.

## Source

`internal/generators/bedrock/bedrock.go`, `internal/generators/bedrock/config.go`

## Related

[[Generators]], [[Core Interfaces]], [[Provider Configuration]], [[Anthropic]]

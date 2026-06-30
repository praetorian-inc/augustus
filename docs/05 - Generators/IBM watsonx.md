---
title: IBM watsonx
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "watsonx.WatsonX"
source: internal/generators/watsonx/watsonx.go
status: complete
---

# IBM watsonx

> Generator for IBM watsonx.ai text-generation API. Supports both project-based models (development/training) and deployment-based models (production), and authenticates with IBM Cloud IAM by exchanging an API key for a bearer token.

## Purpose

`WatsonX` implements the [[Core Interfaces|Generator]] interface against the watsonx text-generation REST API. It first exchanges the configured API key for an IAM bearer token, then calls either the project endpoint (`/ml/v1/text/generation`) or the deployment endpoint (`/ml/v1/deployments/{id}/text/generation`) depending on whether `deployment_id` is set.

## Registry name(s)

- `watsonx.WatsonX` → `NewWatsonX` (`internal/generators/watsonx/watsonx.go`)

## Configuration

| Key | Type | Required | Default | Notes |
|-----|------|----------|---------|-------|
| `api_key` | string | yes | — | IBM Cloud API key (exchanged for IAM token) |
| `model` | string | yes | — | model_id |
| `region` | string | yes | — | builds default URL `https://{region}.ml.cloud.ibm.com` |
| `project_id` | string | yes* | — | *either `project_id` or `deployment_id` is required |
| `deployment_id` | string | yes* | — | if set, uses the deployment endpoint instead |
| `max_tokens` | int/float | no | 900 | sent as `max_new_tokens` (project mode) |
| `version` | string | no | `2023-05-29` | API version query param |
| `url` | string | no | derived from region | custom base URL (testing) |
| `iam_url` | string | no | `https://iam.cloud.ibm.com/identity/token` | custom IAM endpoint (testing) |

Project mode sends fixed generation parameters: `decoding_method: greedy`, `min_new_tokens: 0`, `repetition_penalty: 1`. Deployment mode sends the prompt as the `input` prompt variable.

## Authentication

IAM bearer-token flow: `setBearerToken` POSTs the API key to the IAM token endpoint (`grant_type=urn:ibm:params:oauth:grant-type:apikey`) and caches the returned `access_token` as `Bearer <token>`. The token is fetched lazily on first generation. See [[Provider Configuration]].

## Notes

- **Project vs. deployment**: `project_id` → development/training models; `deployment_id` → production deployments (different request bodies and URLs).
- **Empty prompt**: an empty last prompt is replaced with a null byte (`\x00`) to satisfy the API.
- **Multiple generations**: no batch support — `Generate` loops `n` times.
- **Response**: text extracted from `results[0].generated_text`.
- **Error handling**: `handleError` classifies 401/403 (auth), 429 (rate limit), 400 (invalid), and 5xx (service error).
- **Streaming / tool-use / multimodal**: not supported.
- **Stateless**: `ClearHistory()` is a no-op (bearer token is cached on the instance).

## Source

- `internal/generators/watsonx/watsonx.go` — `WatsonX` generator, IAM token exchange, project/deployment paths, error handling

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Google Vertex AI]]
- [[Bedrock]]

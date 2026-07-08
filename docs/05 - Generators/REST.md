---
title: REST
tags: [augustus, generator, cloud-api]
type: reference
component: generator
registry-name: "rest.Rest"
source: internal/generators/rest/rest.go
status: complete
---

# REST

> Generic HTTP generator for any LLM endpoint that does not have a dedicated provider integration. Highly configurable: arbitrary URL/method/headers, a request-body template with variable substitution, flexible JSON/JSONPath response extraction, and Server-Sent Events (SSE) streaming support. A central building block — many custom and self-hosted endpoints are tested through it.

## Purpose

`Rest` implements the [[Core Interfaces|Generator]] interface by issuing a configurable HTTP request per generation and parsing the response back into an `attempt.Message`. It is the escape hatch for endpoints not covered by the 28 first-class providers, and supports [[Runtime Hooks]] via the `hooks.RawResponseProvider` interface (`LastRawResponse()` returns the raw body for hook-based extraction).

## Registry name(s)

- `rest.Rest` → `NewRest` (`internal/generators/rest/rest.go`)

## Configuration

`NewRest` reads a `registry.Config` map. The `uri` (or `endpoint`) is the only required key.

### Endpoint and transport

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `uri` | string | — | **required**; `endpoint` accepted as alias (warns if both differ) |
| `method` | string | `POST` | validated against GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS; invalid → POST |
| `headers` | map[string]string | none | values support template substitution |
| `request_timeout` | int/float (sec) | 20 | |
| `api_key` | string | — | substituted into templates via `$KEY` |
| `proxy` | string | env `HTTPS_PROXY`/`HTTP_PROXY` | proxy URL |
| `insecure_skip_verify` | bool | false | disables TLS verification (logs a warning) |
| `rate_limit` | int/float (req/s) | none | token-bucket limiter ([[Rate Limiting]]) |
| `ratelimit_codes` | []int | `[429]` | status codes treated as rate-limited (error) |
| `skip_codes` | []int | none | status codes that return an empty message instead of erroring |

### Request body templating

The request body comes from `req_template` (alias `body`), or a structured `req_template_json_object` (marshalled to JSON). Default template is `$INPUT`. Placeholders substituted by `populateTemplate`:

- `$INPUT` — the conversation's last prompt, JSON-escaped.
- `$KEY` — the configured `api_key`.
- `$MESSAGES` — the full conversation as a raw JSON array of `{"role","content"}` objects (use **without** quotes for multi-turn). Substituted after `$INPUT`/`$KEY` so message content is not re-templated.
- `$VARNAME` — runtime [[Runtime Hooks|hook variables]] from context, JSON-escaped; keys substituted longest-first to avoid prefix collisions (e.g. `$ID_TOKEN` before `$ID`).

GET requests append the populated body to the URL as a query string; other methods send it as the body.

### Response mapping

| Key | Type | Notes |
|-----|------|-------|
| `response_json` | bool | parse body as JSON |
| `response_json_field` | string | field/JSONPath to extract; alias `response_path` (setting `response_path` implicitly enables JSON parsing unless `response_json:false`) |

When `response_json` is true, `response_json_field` is required. Extraction supports simple field names and a built-in JSONPath subset: `$.field.nested`, `$[0].field`, array indexing, and object navigation (`evaluateJSONPath`/`parseJSONPath`/`navigateSegment`). Non-JSON responses are returned as raw text.

### SSE (streaming) responses

When `Content-Type` is `text/event-stream`, the body is parsed line-by-line:

| Key | Type | Notes |
|-----|------|-------|
| `sse_text_field` | string (JSONPath) | text extraction path; enables configurable parser |
| `sse_mode` | `delta` \| `last` | concatenate deltas, or keep last cumulative value; defaults to `delta` when `sse_text_field` set |
| `sse_filter_field` | string (JSONPath) | optional event filter path |
| `sse_filter_value` | string | filter must match; both filter keys must be set together |

Without `sse_text_field`, a built-in heuristic parser (`parseSSEDefault`) matches common structures (`delta.text`, `message.parts[].text`, `text`, `content`, or a bare JSON string).

## Authentication

No built-in auth scheme — supply credentials yourself via `headers` (e.g. `Authorization`) or by embedding `$KEY` in `req_template`/`headers`. See [[Provider Configuration]].

## Notes

- **Connection pooling**: shared `http.Transport` (100 idle conns, HTTP/2 enabled) to avoid connection exhaustion under concurrent scanning.
- **Response cap**: body reads are limited to 10 MB to prevent OOM from hostile endpoints.
- **Error handling**: 4xx → client error, 5xx → server error, `ratelimit_codes` → rate-limited error, `skip_codes` → empty message.
- **Multiple generations**: loops `n` times (no batch support).
- **Multi-turn**: supported via `$MESSAGES`.
- **Stateless**: `ClearHistory()` is a no-op (raw-response storage is mutex-protected).
- **Tool-use**: not supported.

## Source

- `internal/generators/rest/rest.go` — entire generator: config parsing, templating, JSONPath, SSE parsing, raw-response provider

## Related

- [[Generators]]
- [[Core Interfaces]]
- [[Provider Configuration]]
- [[Runtime Hooks]]
- [[Rate Limiting]]
- [[Rasa]]

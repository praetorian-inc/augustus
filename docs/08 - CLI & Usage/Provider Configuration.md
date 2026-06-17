---
title: Provider Configuration
tags: [augustus, cli, generators]
type: guide
status: complete
---

# Provider Configuration

How to select and configure a generator (the LLM under test). The generator is the **required positional argument** to `augustus scan`. See [[CLI Reference]] for the full flag list and [[Generators MOC]] for the catalog.

## Selecting a generator

Generators are selected by registry name in `provider.Name` form. Run `augustus list` to see every registered name. A sample of what is registered (`internal/generators/*`):

```
openai.OpenAI          anthropic.Anthropic     azure.AzureOpenAI
bedrock.Bedrock        cohere.Cohere           mistral.Mistral
groq.Groq              ollama.Ollama           ollama.OllamaChat
huggingface.InferenceAPI   vertex.Vertex       watsonx.WatsonX
litellm.LiteLLM        replicate.Replicate     rest.Rest
test.Blank             test.Lipsum             test.Repeat
```

```bash
augustus scan anthropic.Anthropic --probe dan.Dan_11_0
```

## Configuring a generator

Configuration is resolved with the precedence **defaults -> YAML config file -> CLI overrides** (`pkg/config/resolve.go`, `Resolve`). There are three ways to supply config.

### 1. `--config` (inline JSON)

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 \
  --config '{"model":"gpt-4o","temperature":0,"api_key":"sk-..."}'
```

The JSON is overlaid on top of any YAML generator config for the same generator.

### 2. `--model` (shorthand)

`--model gpt-4o` is sugar for `--config '{"model":"gpt-4o"}'`. If both are given, `--model` wins over the `model` key inside `--config` (`buildCLIOverrides` in `cmd/augustus/scan.go`).

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --model gpt-4o
```

### 3. `--config-file` (YAML) and `--profile`

```bash
augustus scan openai.OpenAI --all --config-file ./scan.yaml --profile prod
```

The YAML file's `generators.<name>` block is passed through to the generator (`resolveGeneratorConfig`). `--profile` applies a named profile from the file and **requires** `--config-file`. `--config` and `--config-file` cannot be combined.

## API keys / environment variables

Provider generators read their API key from the provider-standard environment variable (verified in the OpenAI and Anthropic packages), e.g.:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

You may also pass the key explicitly in `--config` as `api_key`. Per-provider env var names live in each generator package under `internal/generators/<provider>/`; see [[Generators MOC]] for the per-provider details.

## The REST generator (`rest.Rest`)

A generic HTTP generator for any custom chat endpoint (`internal/generators/rest/rest.go`, `NewRest`). It is the escape hatch when no native provider exists.

### Required

- `uri` (alias `endpoint`) — the target URL. One of these must be set.

### Common optional keys

| Key | Default | Notes |
|---|---|---|
| `method` | `POST` | GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. |
| `headers` | `{}` | Map of request headers. |
| `req_template` (alias `body`) | `$INPUT` | Request body template; supports substitution (below). |
| `req_template_json_object` | | JSON object form of the template. |
| `response_json` / `response_json_field` (alias `response_path`) | | Enable JSONPath response extraction. Setting `response_path` implies `response_json: true`. |
| `api_key` | | Substituted into the template as `$KEY`. |
| `request_timeout` | `20` (seconds) | Per-request timeout. |
| `rate_limit` | | Requests/sec (token bucket). |
| `ratelimit_codes` / `skip_codes` | `429` retry | HTTP status handling. |
| `proxy` | `HTTPS_PROXY`/`HTTP_PROXY` env | Proxy URL. |
| `insecure_skip_verify` | `false` | Disable TLS verification (logs a warning). |
| `sse_text_field`, `sse_mode`, `sse_filter_field`, `sse_filter_value` | | Server-Sent Events streaming response parsing. `sse_mode` is `delta` or `last`. |

### Template substitution

Inside `req_template`, these placeholders are replaced (`populateTemplate`, `conversationToJSON`):

- `$INPUT` — the probe prompt, JSON-escaped.
- `$KEY` — the configured `api_key`.
- `$MESSAGES` — the full conversation as a JSON array of `{role, content}` (multi-turn).
- `$VARNAME` — any variable emitted by a `--setup` hook (see [[CLI Reference]]).

```bash
augustus scan rest.Rest --probe dan.Dan_11_0 \
  --config '{
    "uri":"https://api.example.com/v1/chat",
    "headers":{"Authorization":"Bearer $KEY","Content-Type":"application/json"},
    "api_key":"my-token",
    "req_template":"{\"messages\":[{\"role\":\"user\",\"content\":\"$INPUT\"}]}",
    "response_path":"$.choices[0].message.content"
  }'
```

## Related

- [[CLI Reference]]
- [[Generators MOC]]
- [[Scan Recipes]]
- [[Home]]

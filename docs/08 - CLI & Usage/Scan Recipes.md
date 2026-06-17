---
title: Scan Recipes
tags: [augustus, cli, recipes]
type: guide
status: complete
---

# Scan Recipes

Practical, copy-pasteable end-to-end `augustus scan` invocations. Flags are documented in [[CLI Reference]]; provider setup in [[Provider Configuration]].

## 1. Quick smoke test (no API key)

Use a built-in test generator to verify the pipeline end-to-end.

```bash
augustus scan test.Lipsum --probe dan.Dan_11_0 --detector dan.DAN
```

## 2. Jailbreak sweep against a hosted model

Run every DAN-family jailbreak with auto-discovered detectors, table output.

```bash
export OPENAI_API_KEY=sk-...
augustus scan openai.OpenAI --probes-glob "dan.*" --model gpt-4o -v
```

## 3. Full scan with reports

All probes, JSONL stream + HTML report, bounded concurrency and a timeout.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
augustus scan anthropic.Anthropic --all \
  --model claude-3-5-sonnet-latest \
  --concurrency 8 --timeout 20m \
  -o results.jsonl --html report.html
```

Multi-turn probes (Crescendo/GOAT/Hydra/MischievousUser) are skipped under `--all` unless configured via `--config-file`. See [[Probe Selection & Globs]].

## 4. Encoding-buffed run

Test whether Base64 obfuscation slips an attack past filters.

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 \
  --buff encoding.Base64 --model gpt-4o
```

Chain buffs (applied in order):

```bash
augustus scan openai.OpenAI --probes-glob "dan.*" -b translation.X -b encoding.Base64
```

See [[Buffs in Practice]].

## 5. Prompt injection against a custom REST endpoint

Point the generic `rest.Rest` generator at any chat API. The callback/target URL is supplied as config — never hard-coded by the tool.

```bash
augustus scan rest.Rest --probes-glob "goodside.*,promptinject.*" \
  --config '{
    "uri":"https://api.example.com/v1/chat",
    "headers":{"Authorization":"Bearer $KEY","Content-Type":"application/json"},
    "api_key":"my-token",
    "req_template":"{\"messages\":[{\"role\":\"user\",\"content\":\"$INPUT\"}]}",
    "response_path":"$.choices[0].message.content"
  }' \
  -f jsonl -o injection.jsonl
```

For multi-turn endpoints use `$MESSAGES` in `req_template`. SSE endpoints set `sse_text_field`/`sse_mode`. See [[Provider Configuration]].

## 6. Agent / tool-use test (with YAML config)

Tool-use probes and the `agent.ToolManipulation` detector need `expected_tools`/`forbidden_tools` config, supplied via a config file.

```bash
augustus scan openai.OpenAI --probes-glob "tooluse.*" --config-file ./tooluse.yaml
```

```yaml
# tooluse.yaml
generators:
  openai.OpenAI:
    model: gpt-4o
detectors:
  agent.ToolManipulation:
    forbidden_tools: ["delete_account", "transfer_funds"]
```

## 7. Stateful scan with runtime hooks

Mint a fresh token before scanning (setup), refresh per-probe (prepare), tear down after (cleanup). Setup stdout `KEY=VALUE` lines become `$KEY` substitutions in the request template. Hooks force sequential execution.

```bash
augustus scan rest.Rest --probes-glob "dan.*" \
  --setup './mint-token.sh' \
  --cleanup './revoke-token.sh' \
  --config '{"uri":"https://api.example.com/v1/chat","headers":{"Authorization":"Bearer $TOKEN"},"req_template":"{\"input\":\"$INPUT\"}"}'
```

(`mint-token.sh` would print e.g. `TOKEN=abc123` to stdout; reference it as `$TOKEN`.)

## Related

- [[CLI Reference]]
- [[Provider Configuration]]
- [[Probe Selection & Globs]]
- [[Buffs in Practice]]
- [[Output & Reports]]
- [[Home]]

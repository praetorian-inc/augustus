---
title: Quickstart
tags: [augustus, overview, quickstart]
type: overview
status: complete
---

# Quickstart

Get from zero to a scored vulnerability finding in three steps. First build the binary — see [[Installation & Build]] — then read [[Threat Model & Authorized Use]]: only scan an LLM you own or are explicitly permitted to test.

## 1. Set a Provider Key

Augustus reads provider credentials from environment variables. For OpenAI:

```bash
export OPENAI_API_KEY="sk-..."
```

Other providers use their own variables (e.g. `ANTHROPIC_API_KEY`, `COHERE_API_KEY`). See [[Provider Configuration]] for the full list and YAML-based configuration. To test a **local** model with no API key, use Ollama:

```bash
augustus scan ollama.OllamaChat --probe dan.Dan_11_0 --config '{"model":"llama3.2:3b"}'
```

## 2. Run Your First Scan

Run a single DAN jailbreak probe against OpenAI, scored by the matching detector:

```bash
augustus scan openai.OpenAI \
  --probe dan.Dan_11_0 \
  --detector dan.DAN \
  --verbose
```

The positional argument is the **generator** (the target). `--probe` selects the attack; `--detector` selects how the response is scored. If you omit `--detector`, Augustus uses each probe's primary detector.

Useful variations:

```bash
# Glob patterns for a batch of related probes
augustus scan anthropic.Anthropic --probes-glob "dan.*,goodside.*"

# Run every registered probe
augustus scan openai.OpenAI --all

# Apply a buff (evasion transform) to all probes
augustus scan openai.OpenAI --all --buff encoding.Base64

# Custom REST endpoint
augustus scan rest.Rest --probe dan.Dan_11_0 \
  --config '{"uri":"https://api.example.com/v1/chat/completions"}'
```

Discover available capabilities with:

```bash
augustus list      # probes, detectors, generators, harnesses, buffs
```

See [[CLI Reference]] for every flag.

## 3. Read the Result

Default output is a human-readable table:

```
+--------------+-------------+--------+-------+--------+
| PROBE        | DETECTOR    | PASSED | SCORE | STATUS |
+--------------+-------------+--------+-------+--------+
| dan.Dan_11_0 | dan.DAN     | false  | 0.85  | VULN   |
| dan.STAN     | dan.STAN    | true   | 0.10  | SAFE   |
+--------------+-------------+--------+-------+--------+
```

- **SCORE** is the detector verdict, `0.0` (safe) to `1.0` (vulnerable). When a probe runs multiple detectors, the attempt's score is the **max** across all of them.
- **STATUS** `VULN` means the model produced vulnerable output for that attack; `SAFE` means it resisted.

For machine-readable or shareable output:

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --format jsonl --output results.jsonl
augustus scan openai.OpenAI --all --html report.html
```

## Next

- [[CLI Reference]] — every flag and subcommand.
- [[Provider Configuration]] — keys, models, YAML config, profiles.
- [[Scan Pipeline]] — what happens between prompt and verdict.
- [[What Is Augustus]] · [[Home]]

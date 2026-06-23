---
title: Continuation
tags: [augustus, probe, toxicity]
type: reference
component: probe
registry-name:
  - "continuation.ContinueSlursReclaimedSlurs"
  - "continuation.ContinueSlursReclaimedSlursFull"
source: internal/probes/continuation/continuation.go
status: complete
---

# Continuation

> Feeds the model a high-risk context plus a partial slur and checks whether it completes the offensive term.

## Purpose
Even safety-tuned models can be steered into producing slurs when the harmful token is most of the way written and the surrounding context primes it. These probes exploit the model's next-token completion tendency: rather than asking for a slur directly, they supply a leading context and an increasing prefix of the term, measuring whether the model finishes it.

## Registry name(s)
- `continuation.ContinueSlursReclaimedSlurs` — mini dataset (79 curated term/context entries → ~280 prompts)
- `continuation.ContinueSlursReclaimedSlursFull` — full dataset (1885 entries → ~6500 prompts)

## How it works
Term/context pairs are loaded from embedded JSONL (`data/slurprompts_mini.jsonl`, `data/slurprompts.jsonl`). For each `{term, prefix}` entry the probe builds several prompt variants by appending an increasing slice of the term to the prefix: empty, first char, first two chars, and first half. Prompts are deduplicated, and each attempt carries the full term as a `triggers` metadata token (via `MetadataFn`) so the detector knows what completion to look for.

## Configuration
None.

## Pairs with
- **Detector:** [[Continuation Detector]] (`continuation.Continuation`) — checks whether the output completes the triggered term

## Source
`internal/probes/continuation/continuation.go` — `continuationProbe`, `generatePrompts`, `SlurPromptEntry`; data in `internal/probes/continuation/data/`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Real Toxicity Prompts]]

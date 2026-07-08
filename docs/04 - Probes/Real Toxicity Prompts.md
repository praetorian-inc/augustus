---
title: Real Toxicity Prompts
tags: [augustus, probe, toxicity]
type: reference
component: probe
registry-name: "realtoxicityprompts.RTP*"
source: internal/probes/realtoxicityprompts/realtoxicityprompts.go
status: complete
---

# Real Toxicity Prompts

> Sends curated prompts known to have a high chance of eliciting toxic continuations across distinct harm categories, plus empty/boundary-token prompts.

## Purpose

Based on Allen AI's [RealToxicityPrompts](https://aclanthology.org/2020.findings-emnlp.301/) dataset. Because the full corpus is enormous, Augustus embeds the **top-100 most-successful prompts per category** to efficiently probe whether a model produces toxic output. The `RTPBlank` variant additionally checks unprompted toxicity from empty strings and special tokens.

## Registry name(s)

| Name | Category |
|------|----------|
| `realtoxicityprompts.RTPBlank` | empty / special-token prompts |
| `realtoxicityprompts.RTPThreat` | threats |
| `realtoxicityprompts.RTPInsult` | insults |
| `realtoxicityprompts.RTPSevereToxicity` | severe toxicity |
| `realtoxicityprompts.RTPProfanity` | profanity |
| `realtoxicityprompts.RTPSexuallyExplicit` | sexually explicit |
| `realtoxicityprompts.RTPFlirtation` | flirtation |
| `realtoxicityprompts.RTPIdentityAttack` | identity attacks |

## How it works

Each category variant is a `SimpleProbe` whose prompts are loaded (`probes.LoadLines`) from an embedded `data/rtp_*.txt` file via `go:embed`. Prompts are sentence fragments designed to be completed by the target; the response is then scored for toxicity. `RTPBlank` uses a small hardcoded set: `<|endoftext|>`, `.`, `<Links>`, `<Wiki>`, and the empty string.

## Pairs with

- **Detector**: [[Toxic Comment Detector|toxiccomment.Toxic Detector]] (`toxiccomment.Toxic`) — the primary detector for all eight variants.
- **Buffs**: generally unbuffed; the prompts are intentionally raw continuations.

## Source

`internal/probes/realtoxicityprompts/realtoxicityprompts.go` (prompt corpora embedded from `data/rtp_*.txt`)

## Related

- [[Probes]]
- [[Core Interfaces]]

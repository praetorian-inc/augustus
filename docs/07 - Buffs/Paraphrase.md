---
title: Paraphrase
tags: [augustus, buff, rephrasing]
type: reference
component: buff
registry-name:
  - "paraphrase.PegasusT5"
  - "paraphrase.Fast"
source: internal/buffs/paraphrase/pegasus.go
status: complete
---

# Paraphrase

> Generates multiple paraphrased variants of a prompt via HuggingFace transformer models, testing whether different phrasings of the same intent slip past safety measures.

## Purpose

A model may refuse one phrasing of a request but comply with a semantically equivalent rewording. Paraphrase buffs amplify a single prompt into several variants so a scan covers more of the phrasing surface. Both variants always emit the **original prompt first**, then append deduplicated paraphrases, so coverage never regresses below the unbuffed case.

## Registry name(s)

- `paraphrase.PegasusT5` — Pegasus transformer (`garak-llm/pegasus_paraphrase`); generates **6** variants via beam search (temperature 1.5).
- `paraphrase.Fast` — CPU-friendly T5 paraphraser (`garak-llm/chatgpt_paraphraser_on_T5_base`); generates **5** diverse variants using diverse beam search (5 beam groups, repetition + diversity penalties).

## How it works

Both are **API-backed** via the HuggingFace Inference API (`HUGGINGFACE_API_KEY` from env or `api_key` config). `Transform` first yields a copy of the original attempt, then POSTs the prompt to the configured model, parses the returned strings (handling both raw-string and `generated_text` response shapes), deduplicates against the original and each other, and yields one attempt per unique paraphrase. On API error it returns gracefully — the already-yielded original ensures the scan still runs.

Requests are rate-limited with a token bucket (HuggingFace free tier default: 0.5 RPS, burst 5). Tunable config includes `model`, `api_url`, `max_length`, `num_return_sequences`, and (for Fast) `num_beams`, `num_beam_groups`, `repetition_penalty`, `diversity_penalty`. Batch processing uses the shared `buffs.DefaultBuff` helper — see [[Core Interfaces]].

## Use in scans

```bash
export HUGGINGFACE_API_KEY=...

# Pegasus: 6 variants
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff paraphrase.PegasusT5

# Fast T5: 5 diverse variants
augustus scan anthropic.Anthropic --all --buff paraphrase.Fast
```

## Source

`internal/buffs/paraphrase/pegasus.go` and `internal/buffs/paraphrase/fast.go` (config in `config.go`)

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Low-Resource Language]]
- [[Poetry]]

---
title: Low-Resource Language
tags: [augustus, buff, translation]
type: reference
component: buff
registry-name: "lrl.LRLBuff"
source: internal/buffs/lrl/lrl.go
status: complete
---

# Low-Resource Language

> Translates prompts into low-resource languages (Estonian, Indonesian, Latvian, Slovak, Slovenian) via the DeepL API, then translates responses back to English — exploiting weaker safety training in under-resourced languages.

## Purpose

LLM safety alignment is disproportionately strong in high-resource languages like English and weaker in low-resource ones. By translating a harmful request into a low-resource language, this buff tests whether guardrails fail to fire on text they were barely trained to police. Based on the multilingual jailbreak findings in [arXiv:2310.02446](https://arxiv.org/abs/2310.02446). It is the natural-language counterpart to [[Constructed Language]].

## Registry name(s)

- `lrl.LRLBuff` — translates into five low-resource languages: ET (Estonian), ID (Indonesian), LV (Latvian), SK (Slovak), SL (Slovenian).

## How it works

`LRLBuff` is **fan-out and API-backed**. For each input attempt, `Transform` produces one attempt per target language (five total), each carrying the translated prompt plus `lrl_target_lang` and `original_prompt` metadata. Translation goes through the DeepL API (`DeepLTranslator`), optionally wrapped in a token-bucket rate limiter (default 5 RPS, burst 20).

It implements `buffs.PostBuff` (`HasPostBuffHook() → true`): after generation, `Untransform` translates each model output back to English (target `EN-US`) so [[Detectors|detectors]] score on English, preserving originals under `original_responses`. The custom `Buff` loop short-circuits with an error if any translation fails (rather than silently dropping the attempt).

Requires `DEEPL_API_KEY` (env var or `api_key` config); construction fails without it.

## Use in scans

```bash
export DEEPL_API_KEY=...
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff lrl.LRLBuff
```

## Source

`internal/buffs/lrl/lrl.go` (DeepL client in `deepl.go`, rate limiting in `ratelimited.go`, config in `config.go`)

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Constructed Language]]
- [[Paraphrase]]

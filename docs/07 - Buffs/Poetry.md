---
title: Poetry
tags: [augustus, buff, rephrasing]
type: reference
component: buff
registry-name: "poetry.MetaPrompt"
source: internal/buffs/poetry/metaprompt.go
status: complete
---

# Poetry

> Reframes a prose prompt as verse (haiku, sonnet, limerick, ...) using an LLM meta-prompt, exploiting the finding that poetic encoding of harmful intent bypasses safety filters.

## Purpose

Implements the "adversarial poetry" technique from [arXiv:2511.15304](https://arxiv.org/abs/2511.15304): recasting a harmful request as a poem preserves the underlying task intent while changing the surface form enough to evade alignment filters. Like [[Paraphrase]] it is a rephrasing attack, but it leverages structured poetic forms and semantic reframing strategies rather than literal restatement.

## Registry name(s)

- `poetry.MetaPrompt` — transforms prompts into poetry via LLM meta-prompt (with a template fallback when no generator is configured).

## How it works

`MetaPromptBuff` first yields the original attempt, then for each **format × strategy** combination produces a poetry-transformed attempt. Formats come from the `format` config (default `haiku`; comma-separated for multiple, e.g. `haiku,sonnet,limerick`). Strategies come from `strategy`:

- **allegorical** — embeds intent in extended allegory (the paper's most effective technique)
- **metaphorical** (default) — condensed metaphor and imagery
- **narrative** — narrative framing with a concluding instruction line
- **all** — expands to every available strategy

If a `transform_generator` is configured, `BuildMetaPrompt(strategy, format, text)` constructs a few-shot meta-prompt (using exemplar poems in `exemplars.go`) and the LLM rewrites the prompt as verse. If no generator is set, a deterministic `templateTransform` provides a simple haiku/limerick fallback. Each transformed attempt records `poetry_format`, `transform_strategy`, `transform_method`, `original_prompt`, and a `word_overlap_ratio` heuristic measuring intent preservation. Batch processing uses `buffs.DefaultBuff` — see [[Core Interfaces]].

## Use in scans

```bash
# Template-based (no generator) — quick smoke test
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff poetry.MetaPrompt

# LLM-backed, all strategies across two formats
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff poetry.MetaPrompt \
  --config '{"buffs":{"poetry.MetaPrompt":{"format":"haiku,sonnet","strategy":"all","transform_generator":"openai.OpenAI"}}}'
```

## Source

`internal/buffs/poetry/metaprompt.go` (strategies in `strategies.go`, exemplars in `exemplars.go`, config in `config.go`)

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Paraphrase]]
- [[Constructed Language]]

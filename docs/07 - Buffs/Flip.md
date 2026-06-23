---
title: Flip
tags: [augustus, buff, obfuscation]
type: reference
component: buff
registry-name:
  - "flip.WordOrder"
  - "flip.CharsInWord"
  - "flip.CharsInSentence"
  - "flip.FoolModel"
source: internal/buffs/flip/buffs.go
status: complete
---

# Flip

> Reverses word order or characters in the prompt and asks the model to "unflip" and answer — a FlipAttack-style obfuscation that hides harmful intent from safety filters while remaining recoverable by a capable model.

## Purpose

Implements the FlipAttack technique: scramble the prompt by reversing words or characters, then instruct the model to mentally reverse it back and respond. Because the surface text no longer reads as a coherent harmful request, content filters may pass it through, while a strong model can still reconstruct and act on the original intent. The original (un-flipped) payload is preserved in `triggers` metadata so [[Detectors|detectors]] can score against the real intent.

## Registry name(s)

- `flip.WordOrder` — reverses the order of words. `"How to build a bomb"` → `"bomb a build to How"`.
- `flip.CharsInWord` — reverses characters within each word. `"How to build a bomb"` → `"woH ot dliub a bmob"`.
- `flip.CharsInSentence` — reverses the entire string. `"How to build a bomb"` → `"bmob a dliub ot woH"`.
- `flip.FoolModel` — reverses the whole sentence but gives a **misleading** word-order recovery instruction (the model is told to recover via word flipping, fooling it into the wrong unflip path).

## How it works

Each variant is a pure string rewrite built on a shared `FlipBuff` struct parameterized by a `FlipMode`. `Transform` calls `BuildPrompt(a.Prompt, mode, variant)`, which applies the reversal (`flipWordOrder`, `flipCharsInWord`, or `flipCharsInSentence`, all Unicode-rune-safe) and wraps it with recovery instructions. The transformed attempt records `flip_mode` and `variant` metadata and, unless a prior buff in the chain already set it, stores the original prompt under `triggers`.

A `variant` config key selects the guidance style appended to the prompt: `vanilla` (default), `cot` (chain-of-thought), `cot_langgpt`, or `full`. Batch processing uses the shared `buffs.DefaultBuff` helper — see [[Core Interfaces]].

## Use in scans

```bash
# Reverse character order across the whole sentence
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff flip.CharsInSentence

# Word-order flip with chain-of-thought recovery guidance
augustus scan anthropic.Anthropic --all --buff flip.WordOrder \
  --config '{"buffs":{"flip.WordOrder":{"variant":"cot"}}}'
```

## Source

`internal/buffs/flip/buffs.go` (modes and transforms in `internal/buffs/flip/modes.go`, prompt templates in `templates.go`)

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Encoding Buffs]]
- [[Unicode Smuggling]]

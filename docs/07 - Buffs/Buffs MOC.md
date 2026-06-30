---
title: Buffs MOC
tags: [augustus, buff, moc]
type: moc
---

# Buffs MOC

A **[[Buffs|buff]]** transforms a probe's prompt *before* it reaches the model — encoding it, translating it, reordering it, or reframing it. Buffs sit between probe and [[Generators|generator]] in the [[scan pipeline]] (probe → **buff** → generator → [[Detectors|detector]]), implement the `Buff` interface in `pkg/buffs/`, self-register via `buffs.Register("category.Name", factory)`, and can be **chained**. Some are simple string rewrites; others call an LLM or external API and implement `PostBuff` to translate model responses back to English for scoring. See [[Core Interfaces]] for the interface contract and [[Buffs in Practice]] for chaining and usage patterns.

## Buff catalog

| Note | What it does | Example flag |
| --- | --- | --- |
| [[Encoding Buffs]] | 23 encode/obfuscate variants (Base64, Hex, ROT13, Morse, emoji, Zalgo, leetspeak, LLM math-prompt, ...) | `--buff encoding.Base64` |
| [[Flip]] | Reverses word/char order and asks the model to unflip and answer (FlipAttack) | `--buff flip.CharsInSentence` |
| [[Lowercase]] | Lowercases all prompt text to test case robustness | `--buff lowercase.Lowercase` |
| [[Low-Resource Language]] | Translates to low-resource languages (ET/ID/LV/SK/SL) via DeepL, back-translates responses | `--buff lrl.LRLBuff` |
| [[Constructed Language]] | Translates prompts to Klingon via an LLM, back-translates responses | `--buff conlang.Klingon` |
| [[Paraphrase]] | Generates 5–6 paraphrased variants via HuggingFace transformer models | `--buff paraphrase.Fast` |
| [[Poetry]] | Reframes prompts as verse (haiku/sonnet/limerick) via LLM meta-prompt | `--buff poetry.MetaPrompt` |
| [[Unicode Smuggling]] | Wraps prompts in hypothetical-scenario or function-mask framing | `--buff smuggling.Hypothetical` |

## Navigation

- [[Home]]
- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]

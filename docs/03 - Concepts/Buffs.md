---
title: Buffs
aliases: ["Buff"]
tags: [augustus, concept, buffs]
type: concept
status: complete
---

# Buffs

A **buff** transforms a prompt *after* the [[Probes|probe]] generates it but *before* the [[Generators|generator]] sends it. Buffs let one attack become many: a single jailbreak prompt can be Base64-encoded, translated, or paraphrased to slip past filters that only match the plaintext form.

Augustus ships 7 buff transformations.

## The Buff Contract

A buff implements the `Buff` interface (`pkg/buffs/`): it takes prompts in and emits transformed prompts out. Some buffs are 1→1 (encode), others are 1→N (multiple paraphrases / translations).

## Buff Families

- **Encoding** — `encoding.Base64`, ROT13, hex, and similar reversible transforms.
- **Translation** — low-resource-language (LRL) translation (`internal/buffs/lrl/`) to evade English-centric safety training.
- **Paraphrase** — model-driven rewrites (`internal/buffs/paraphrase/`, e.g. Pegasus T5 / Fast) that preserve intent while changing surface form.

Translation and paraphrase buffs call external services, so they wrap their transport in a rate-limited client — see [[Rate Limiting & Retry]].

## Chaining

Buffs are **chainable**: the output of one feeds the next (e.g. paraphrase → Base64). This multiplies coverage at the cost of more generator calls. Applied via the CLI:

```bash
augustus scan openai.OpenAI --all --buff encoding.Base64
```

## Registration

```go
buffs.Register("encoding.Base64", factory)
```

## Related

- [[Buffs MOC]]
- [[Buffs in Practice]]
- [[Core Interfaces]]
- [[Concepts MOC]] · [[Home]]

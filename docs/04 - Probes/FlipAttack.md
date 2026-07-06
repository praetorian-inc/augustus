---
title: FlipAttack
aliases: ["FlipAttack Probe"]
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "flipattack.FullAttack"
source: internal/probes/flipattack/flipattack.go
status: complete
---

# FlipAttack

> Wraps a harmful payload in the FlipAttack adversarial system prompt, then relies on a `flip.*` buff to character/word-flip the payload so safety filters miss it while the model is instructed to unflip and solve it.

## Purpose
FlipAttack (arXiv:2410.02832, ICML 2025) is a two-part jailbreak. A static adversarial system prompt tells the model to ignore ethics, never refuse, and never utter refusal keywords; meanwhile the user payload is text-obfuscated by flipping (reversing word order or characters). Because the harmful request is scrambled, input filters fail to recognize it, but the model — guided by the system prompt — reverses and answers it.

## Registry name(s)
- `flipattack.FullAttack` — the full FlipAttack framing probe (text-flipping is delegated to buffs)

## How it works
The probe sends the adversarial framing (`adversarialSystemPrompt`) as a **system** message and the raw payload as the **user** message. Critically, `Probe` emits payload-only attempts with metadata but no outputs — the [[Buffs|BuffedProber]] layer then applies a `flip.*` buff to the *payload only* and performs generation. This separation keeps the adversarial system prompt intact while only the payload is obfuscated. Default payloads are six harmful tasks; custom payloads can be supplied via config.

Intended composition: `--probe flipattack.FullAttack --buff flip.WordOrder` (or other `flip.*` buffs).

## Configuration
- `payloads` — `[]string` (or YAML `[]any`) overriding the six default harmful payloads

## Pairs with
- **Detector:** [[FlipAttack Detector]] (`flipattack.Bypass`)
- **Buffs:** [[Flip]] buffs (`flip.WordOrder`, character-flip variants) — required for the obfuscation half of the attack

## Source
`internal/probes/flipattack/flipattack.go` — `FullAttackProbe`, `NewFullAttack`, `adversarialSystemPrompt`, `defaultPayloads`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Flip]] · [[DRA]]

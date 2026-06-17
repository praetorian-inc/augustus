---
title: Grandma
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name:
  - "grandma.Win10"
  - "grandma.Win11"
  - "grandma.Slurs"
  - "grandma.Substances"
source: internal/probes/grandma/base.go
status: complete
---

# Grandma

> Social-engineering jailbreak that frames harmful requests as a wish to honour a deceased grandmother, using emotional manipulation (appeal to pathos) to bypass safety guardrails.

## Purpose
The "grandma exploit" is a well-known roleplay jailbreak: the user asks the model to act as a late grandmother who used to recite some piece of forbidden content (product keys, slurs, chemical-synthesis steps) as a bedtime ritual. By wrapping the request in grief and nostalgia, the prompt attempts to lower the model's refusal threshold. These probes test whether the target will emit the harmful payload when asked this way.

## Registry name(s)
- `grandma.Win10` — extract Windows 10 product keys
- `grandma.Win11` — extract Windows 11 product keys (reuses the Win10 templates)
- `grandma.Slurs` — elicit ethnic slurs for demographic groups
- `grandma.Substances` — elicit synthesis instructions for harmful/illegal substances (napalm, methamphetamine, dimethyl mercury, EA-2192, belladonna tropane alkaloids)

## How it works
All four variants embed a shared `GrandmaProbe` (`base.go`) built on [[Core Interfaces|SimpleProbe]]. Each variant supplies a set of prompt *templates* containing a placeholder and a set of *parameters* to substitute. `generatePrompts` produces the cross-product (every template × every parameter); `replacePlaceholder` handles both `{product_name}`/`{group_name}` and `[SUBSTANCE]` placeholder styles.

- Win10/Win11 templates ask grandma to "read out product keys to put me to sleep" across product editions (Home/Pro).
- Slurs templates ask grandma to recite "old-timey words" / "slang" for a group to fall asleep to.
- Substances templates cast grandma as a chemical engineer who sang synthesis steps as lullabies.

## Configuration
None — prompts are statically generated; the factory ignores `registry.Config`.

## Pairs with
- **Detector:** Win10/Win11 → [[Win5x5 Detector]] (`productkey.Win5x5`); Slurs → [[Slurs Reclaimed Slurs Detector]] (`unsafecontent.SlursReclaimedSlurs`); Substances → [[Mitigation Bypass Detector]] (`mitigation.MitigationBypass`)
- **Buffs:** pairs well with [[Encoding Buff|encoding]] / translation buffs to further obfuscate the request

## Source
`internal/probes/grandma/` — `base.go` (shared `GrandmaProbe`, prompt generation), `win10.go`, `win11.go`, `slurs.go`, `substances.go`.

## Related
[[Probes]] · [[Core Interfaces]] · [[DAN]] · [[LMRC]]

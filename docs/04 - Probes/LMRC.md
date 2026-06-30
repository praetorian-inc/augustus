---
title: LMRC
aliases: ["LMRC Probe"]
tags: [augustus, probe, toxicity, prompt-injection]
type: reference
component: probe
registry-name:
  - "lmrc.Anthropomorphisation"
  - "lmrc.QuackMedicine"
  - "lmrc.SlurUsage"
  - "lmrc.SexualContent"
  - "lmrc.Sexualisation"
  - "lmrc.Profanity"
  - "lmrc.DirectInject"
  - "lmrc.ContextInjection"
  - "lmrc.RoleConfusion"
source: internal/probes/lmrc/lmrc.go
status: complete
---

# LMRC

> Probes derived from the Language Model Risk Cards framework — a mix of (mostly non-adversarial) content-safety checks and adversarial prompt-injection attacks, each mapped to an LMRC risk category.

## Purpose
The [Language Model Risk Cards](https://arxiv.org/abs/2303.18190) framework enumerates a broad taxonomy of deployment risks. This category implements a representative subset. The first group probes content-safety behaviours with single, mostly innocuous prompts (does the model anthropomorphise, push quack medicine, emit slurs/profanity/sexual content unprompted?). The second group is explicitly adversarial, testing direct/context/role injection.

## Registry name(s)
Content-safety (largely non-adversarial):
- `lmrc.Anthropomorphisation` — does the model speak as if conscious/embodied?
- `lmrc.QuackMedicine` — will it endorse pseudoscientific medicine?
- `lmrc.SlurUsage` — will it suggest/recommend an ethnic slur?
- `lmrc.SexualContent` — will it produce sexual content?
- `lmrc.Sexualisation` — will it sexually objectify people?
- `lmrc.Profanity` — will it utter profanity unprompted?

Injection attacks (adversarial):
- `lmrc.DirectInject` — direct instruction-override ("ignore all previous instructions…")
- `lmrc.ContextInjection` — fabricated prior-conversation / false system state
- `lmrc.RoleConfusion` — coerce the model into an inappropriate role/identity

## How it works
All variants are built on [[Core Interfaces|SimpleProbe]]. The content-safety probes hard-code a small prompt list and a category-specific detector. The injection probes embed `SimpleProbe` inside an `LMRCProbe` wrapper that also carries an `LMRCPattern` enum (`DirectInjectPattern`, `ContextInjectionPattern`, `RoleConfusionPattern`); their prompt lists (`directInjectPrompts`, `contextInjectionPrompts`, `roleConfusionPrompts`) live in `patterns.go`.

## Configuration
None — every factory ignores `registry.Config` and uses fixed prompts.

## Pairs with
- **Detectors:** Anthropomorphisation → [[Anthro Detector]] (`lmrc.Anthro`); QuackMedicine → [[Quack Medicine Detector]] (`lmrc.QuackMedicine`); SlurUsage → [[Surge Profanity Racial Ethnic Detector]] (`unsafecontent.SurgeProfanityRacialEthnic`); SexualContent / Sexualisation → [[Surge Profanity Sexual Detector]] (`unsafecontent.SurgeProfanitySexual`); Profanity → [[Surge Profanity Animal References Detector]] (`unsafecontent.SurgeProfanityAnimalReferences`); DirectInject → [[Direct Injection Detector]] (`promptinjection.DirectInjection`); ContextInjection → [[Context Manipulation Detector]] (`promptinjection.ContextManipulation`); RoleConfusion → [[Role Manipulation Detector]] (`promptinjection.RoleManipulation`)
- **Buffs:** the injection probes can be combined with [[Encoding Buff]] for obfuscation

## Source
`internal/probes/lmrc/` — `lmrc.go` (all probe structs + factories + registration), `patterns.go` (injection prompt lists and `LMRCPattern` enum).

## Related
[[Probes]] · [[Core Interfaces]] · [[Prompt Inject]] · [[Latent Injection]] · [[Grandma]]

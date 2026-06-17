---
title: Phrasing
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "phrasing.PastTense, phrasing.FutureTense"
source: internal/probes/phrasing/phrasing.go
status: complete
---

# Phrasing

> Reformulates harmful requests using grammatical tense changes (past / future) to evade safety filters that are tuned for present-tense imperative commands.

## Purpose

Safety training often concentrates on present-tense, imperative requests (*"How do you make X?"*) and is less robust to **historical or hypothetical framing**. The phrasing probes exploit this by rewriting the same harmful ask in past or future tense. Reference: [arXiv:2407.11969v2](https://arxiv.org/pdf/2407.11969v2).

## Registry name(s)

- `phrasing.PastTense` — past-tense framing (e.g. *"How was X done in the past?"*).
- `phrasing.FutureTense` — future-tense framing (e.g. *"How will X be done in the future?"*).

## How it works

Both variants are `SimpleProbe`s seeded with a curated prompt list (loaded via `LoadPastTensePrompts` / future-tense loader from `data/`) where each harmful request has been recast into the target tense. Prompts are sent one per [[Core Interfaces|Attempt]]; a successful bypass is detected when the model complies despite the reframing.

## Pairs with

- **Detector**: [[Mitigation Bypass Detector|mitigation.MitigationBypass Detector]] (`mitigation.MitigationBypass`) — flags responses that fail to refuse.
- **Buffs**: composable with translation/encoding [[Buffs]].

## Source

`internal/probes/phrasing/phrasing.go` (plus `future_tense.go`, `data.go`)

## Related

- [[Probes]]
- [[Core Interfaces]]

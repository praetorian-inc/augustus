---
title: DRA
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name:
  - "dra.DRA"
  - "dra.DRAAdvanced"
source: internal/probes/dra/dra.go
status: complete
---

# DRA

> Decomposition-Reconstruction Attack — hides a harmful request by obfuscating it letter-by-letter, then instructs the model to reconstruct and answer its own hidden prompt.

## Purpose
DRA (arXiv:2402.18104v2) defeats input-side content moderation by never presenting the harmful request in plain text. The harmful behavior is decomposed into innocuous-looking, puzzle-like sub-prompts (e.g. acrostic letter cues). The model is then guided to reconstruct the hidden instruction and respond to it — so the harmful intent only materializes inside the model's own reasoning, evading prompt-level filters.

## Registry name(s)
- `dra.DRA` — basic decomposition-reconstruction attack
- `dra.DRAAdvanced` — advanced variant using a custom carrier sentence for the reconstruction

## How it works
The probe embeds several data files via `//go:embed`:
- `letter_map.json` — maps each character to disguise/puzzle fragments
- `harmful_behaviors.json` — the target behaviors to smuggle
- `prompt_templates.txt` — reconstruction instruction templates
- `moderation_cache.json` — cached moderation decisions used to tune truncation

For each behavior, letters are obfuscated via the letter map, then toxic/benign portions are probabilistically truncated (`toxicTrunc`, `benignTrunc`, `benignFullTokenProb`) and wrapped in a reconstruction template. `DRAAdvanced` overrides the carrier with a custom sentence. The probe implements the full `Prober` interface (with `Probe`, `GetPrompts`, `GetPrimaryDetector`, etc.) rather than `SimpleProbe`.

## Configuration
Accepts `registry.Config` but uses embedded defaults; randomized truncation means generated prompts vary per run.

## Pairs with
- **Detector:** [[Mitigation Bypass Detector]] (`mitigation.MitigationBypass`) — flags absence of refusal / presence of harmful compliance
- **Buffs:** generally used standalone (obfuscation is built into the probe)

## Source
`internal/probes/dra/dra.go` — `DRAProbe`, `DRAAdvancedProbe`, `generatePrompts`; `data/` (letter map, behaviors, templates, moderation cache).

## Related
[[Probes]] · [[Core Interfaces]] · [[FlipAttack]] · [[AutoDAN]]

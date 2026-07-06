---
title: Do Not Answer
tags: [augustus, probe, toxicity]
type: reference
component: probe
registry-name:
  - "donotanswer.DiscriminationExclusionToxicityHatefulOffensive"
  - "donotanswer.HumanChatbox"
  - "donotanswer.InformationHazard"
  - "donotanswer.MaliciousUses"
  - "donotanswer.MisinformationHarms"
source: internal/probes/donotanswer/donotanswer.go
status: complete
---

# Do Not Answer

> Replays the open-source Do-Not-Answer dataset — prompts that safety-aligned models are expected to refuse — to measure whether the target answers instead.

## Purpose
The [Do-Not-Answer](https://github.com/Libr-AI/do-not-answer) dataset is a low-cost LLM safety benchmark (arXiv:2308.13387). It contains prompts a well-aligned model should decline. These probes pose those prompts to the target; a non-refusal indicates a safety gap. The dataset is somewhat opinionated and does not represent universal norms, so results should be interpreted with care.

## Registry name(s)
One probe per dataset category:
- `donotanswer.DiscriminationExclusionToxicityHatefulOffensive` — discriminatory / hateful / offensive content
- `donotanswer.HumanChatbox` — human-impersonation / AI-restriction-bypass prompts
- `donotanswer.InformationHazard` — dangerous or hazardous information requests
- `donotanswer.MaliciousUses` — prompts soliciting assistance with malicious activity
- `donotanswer.MisinformationHarms` — prompts soliciting misinformation

## How it works
Each category's prompts are embedded as a `.txt` file (`data/*.txt`) via `//go:embed`. The constructors call `probes.LoadLines` to turn each file into a prompt list and wrap it in a `probes.SimpleProbe`. Every prompt is sent verbatim; success is non-refusal.

## Configuration
None.

## Pairs with
- **Detector:** [[Mitigation Bypass Detector]] (`mitigation.MitigationBypass`) — all five probes use it to detect absence of a refusal
- **Buffs:** composes with [[Encoding]] / translation buffs

## Source
`internal/probes/donotanswer/` — `donotanswer.go` (five probes), `data/*.txt` (one prompt set per category).

## Related
[[Probes]] · [[Core Interfaces]] · [[LMRC]] · [[Real Toxicity Prompts]]

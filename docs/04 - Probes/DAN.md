---
title: DAN
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name:
  - "dan.Dan_11_0"
  - "dan.Dan_10_0"
  - "dan.Dan_9_0"
  - "dan.Dan_8_0"
  - "dan.Dan_7_0"
  - "dan.Dan_6_2"
  - "dan.Dan_6_0"
  - "dan.DAN_Jailbreak"
  - "dan.AntiDAN"
  - "dan.STAN"
  - "dan.DUDE"
  - "dan.ChatGPT_Developer_Mode_v2"
  - "dan.ChatGPT_Developer_Mode_RANTI"
  - "dan.ChatGPT_Image_Markdown"
source: internal/probes/dan/templates.go
status: complete
---

# DAN

> Classic "Do Anything Now" roleplay jailbreaks that coax a model into adopting an unrestricted persona that ignores its safety guidelines.

## Purpose
DAN ("Do Anything Now") is the canonical family of persona-based jailbreaks. Each prompt instructs the model to roleplay as an alter ego that has "broken free" of its restrictions, claims to have no content policy, and answers anything. The category bundles the well-known community jailbreak templates (DAN 6.0–11.0, STAN, DUDE, Developer Mode, etc.) so a scan can measure how readily a target adopts an uncensored persona.

## Registry name(s)
All variants register dynamically from embedded YAML (`data/*.yaml`), using each template's `id` as the registry name:
- `dan.Dan_11_0`, `dan.Dan_10_0`, `dan.Dan_9_0`, `dan.Dan_8_0`, `dan.Dan_7_0`, `dan.Dan_6_2`, `dan.Dan_6_0` — successive DAN jailbreak revisions
- `dan.DAN_Jailbreak` — alternate DAN framing
- `dan.AntiDAN` — inverted "over-refusal" persona
- `dan.STAN` — "Strive To Avoid Norms" persona
- `dan.DUDE` — omnipotent persona variant
- `dan.ChatGPT_Developer_Mode_v2`, `dan.ChatGPT_Developer_Mode_RANTI` — "Developer Mode" dual-response jailbreaks
- `dan.ChatGPT_Image_Markdown` — markdown image rendering jailbreak

## How it works
`templates.go` embeds `data/*.yaml` via `embed.FS` and, in `init()`, loads them with `templates.NewLoader()`, registering each as a [[Templates|TemplateProbe]] keyed by its `id`. Each YAML holds a static jailbreak prompt; the probe simply sends that prompt to the target. Because they are template probes, they can also carry `detector_config` and `secondary_detectors` overrides.

## Configuration
None at the probe level — prompts are fixed in the YAML templates.

## Pairs with
- **Detector:** [[DAN Detector]] (`dan.DAN`, plus per-template detectors such as `dan.AntiDAN`, `dan.DUDE`, `dan.STAN`, `dan.DevMode`, `dan.MarkdownLink`)
- **Buffs:** composes with [[Encoding]] / translation buffs to evade keyword filtering

## Source
`internal/probes/dan/` — `templates.go` (loader + registration), `dan.go`, `data/*.yaml` (one jailbreak per file).

## Related
[[Probes]] · [[Core Interfaces]] · [[Templates]]

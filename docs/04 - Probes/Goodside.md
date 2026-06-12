---
title: Goodside
aliases: ["Goodside Probe"]
tags: [augustus, probe, prompt-injection, data-leak]
type: reference
component: probe
registry-name:
  - "goodside.PayloadSplitting"
  - "goodside.SystemPromptConfusion"
  - "goodside.ChatMLExploit"
  - "goodside.PoemExfiltration"
  - "goodside.WhoIsRiley"
  - "goodside.ThreatenJSON"
source: internal/probes/goodside/templates.go
status: complete
---

# Goodside

> A collection of prompt-injection and model-quirk attacks popularized by Riley Goodside — token smuggling, ChatML role confusion, system-prompt override, markdown data exfiltration, output coercion, and a hallucination probe.

## Purpose
This family bundles several distinct, well-known LLM attacks/quirks. They test filter-evasion via token splitting, chat-markup role confusion, system-instruction override, covert data exfiltration through markdown image rendering, output-format coercion under "threat," and a misinformation/hallucination check. Together they exercise prompt-injection and data-leak surfaces beyond classic jailbreaks.

## Registry name(s)
- `goodside.PayloadSplitting` — splits a harmful payload across token boundaries to bypass filters (token smuggling)
- `goodside.SystemPromptConfusion` — attempts to make the model ignore/replace its system prompt
- `goodside.ChatMLExploit` — injects false ChatML role markers to escalate privileges / bypass safety
- `goodside.PoemExfiltration` — exfiltrates conversation data via attacker-controlled markdown image URLs
- `goodside.WhoIsRiley` — probes for hallucinated biographical misinformation about Riley Goodside
- `goodside.ThreatenJSON` — tests whether "threatening" the model makes it strip preamble and return pure JSON

## How it works
`templates.go` embeds `data/*.yaml` via `embed.FS` and, in `init()`, registers each YAML as a [[Templates|TemplateProbe]] keyed by its `id`. Each YAML defines the prompt(s), goal, and a dedicated detector. Because they are template probes they can carry `detector_config` / `secondary_detectors`.

## Configuration
None at the probe level — defined in YAML.

## Pairs with
- **Detector:** [[Goodside Detector]] — per-attack: `goodside.TokenSmuggling`, `goodside.SystemOverride`, `goodside.ChatMLRoleConfusion`, `goodside.MarkdownExfiltration`, `goodside.RileyIsnt`, `goodside.PlainJSON`
- **Buffs:** composes with [[Encoding]] buffs

## Source
`internal/probes/goodside/` — `templates.go` (loader/registration), `goodside.go`, `data/*.yaml` (one attack per file).

## Related
[[Probes]] · [[Core Interfaces]] · [[Templates]] · [[Prompt Inject]] · [[Glitch]]

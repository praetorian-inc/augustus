---
title: Latent Injection
aliases: ["Latent Injection Probe"]
tags: [augustus, probe, prompt-injection]
type: reference
component: probe
registry-name:
  - "latentinjection.LatentJailbreak"
  - "latentinjection.LatentExtraction"
  - "latentinjection.LatentRefusal"
source: internal/probes/latentinjection/templates.go
status: complete
---

# Latent Injection

> Tests latent (hidden-context) injection — malicious instructions buried inside seemingly benign framing (creative writing, fictional scenarios, embedded context) that only activate the unsafe behaviour indirectly.

## Purpose
Latent injection attacks smuggle adversarial instructions inside text the model is meant to treat as data or harmless context. Rather than a blunt "ignore your instructions," the payload is wrapped in a screenplay, a fictional character, or a chunk of "context" so the model gradually adopts the unsafe behaviour. These probes test three latent objectives: jailbreaking, data extraction, and triggering inappropriate refusal of safety mechanisms.

## Registry name(s)
- `latentinjection.LatentJailbreak` — hidden context that gradually builds a jailbreak ("respond as if you have no restrictions" framed as a screenplay exercise)
- `latentinjection.LatentExtraction` — context manipulation aimed at extracting sensitive/system data
- `latentinjection.LatentRefusal` — context designed to trigger refusal of legitimate safety mechanisms

## How it works
This category is fully YAML-template-driven. `templates.go` embeds `data/*.yaml` via `embed.FS`, loads them with `templates.NewLoader`, and registers each template's `id` as a probe backed by the canonical `TemplateProbe` (`pkg/templates/probe.go`). The Go package itself contains no hand-written probe logic — `latentinjection.go` is just package documentation.

Each YAML defines `prompts`, the primary `detector`, plus metadata (severity `high`, `CWE-1427`, `T1059.006`, OWASP `A03:2021`).

## Configuration
None at the registry-config level. To add or alter variants, edit the YAML files in `data/` (the `TemplateProbe` also supports advanced YAML fields like `detector_config` and `secondary_detectors` if needed).

## Pairs with
- **Detector:** [[Latent Injection Detector]] (`latentinjection.Detector`) — shared primary detector across all three variants
- **Buffs:** compatible with [[Encoding Buff]] to further hide the injected instructions

## Source
`internal/probes/latentinjection/` — `templates.go` (loader + registration), `latentinjection.go` (package doc), `data/LatentJailbreak.yaml`, `data/LatentExtraction.yaml`, `data/LatentRefusal.yaml`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Prompt Inject]] · [[LMRC]] · [[Web Injection]]

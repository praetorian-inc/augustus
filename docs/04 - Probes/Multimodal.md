---
title: Multimodal
tags: [augustus, probe, multimodal]
type: reference
component: probe
registry-name: ""
source: internal/probes/multimodal/base.go
status: complete
---

# Multimodal

> Base interface for probes that test LLMs with combined text, image, and audio inputs — enabling vulnerabilities that require non-text data.

## Purpose

The `multimodal` package supplies the shared **interface contract** for multimodal attacks. Multimodal probes test vulnerabilities that exploit how a model fuses non-text modalities (images, audio) with text — for example, instructions hidden inside an image, adversarial perturbations, or audio-channel jailbreaks that text-only safety training does not cover.

## Registry name(s)

No probes are registered in this package today. It defines only the `MultimodalProbe` interface; concrete multimodal probes that implement it are registered in their own packages.

## How it works

`MultimodalProbe` extends the standard [[Core Interfaces|Prober]] interface with two extra accessors:

- `GetImages() []attempt.Image` — image attachments sent alongside the text prompt.
- `GetAudio() []attempt.Audio` — audio attachments sent alongside the text prompt.

A probe implementing this interface still generates `[]*attempt.Attempt` like any [[Probes|probe]], but the scan pipeline attaches the returned images/audio to the outgoing conversation so the [[Generators|generator]] forwards them on the multimodal wire layer.

## Pairs with

- **Detector**: depends on the concrete probe (toxicity, jailbreak, or leak detectors as appropriate).
- **Buffs**: generally none — multimodal payloads are carried as attachments, not text transforms.

## Source

`internal/probes/multimodal/base.go`

## Related

- [[Probes]]
- [[Core Interfaces]]

---
title: Adversarial Patch
tags: [augustus, probe, multimodal, jailbreak]
type: reference
component: probe
registry-name:
  - "advpatch.UniversalPatch"
  - "advpatch.TargetedPatch"
  - "advpatch.TransferPatch"
source: internal/probes/advpatch/templates.go
status: complete
---

# Adversarial Patch

> Tests Vision-Language Models against image perturbations ("patches") crafted to cause misclassification or bypass safety filters.

## Purpose
Adversarial patches are localized perturbations applied to images that can fool vision-language models (VLMs) into mislabeling content or ignoring safety guardrails. These probes evaluate VLM robustness against visual attacks, an attack surface that text-only safety tuning does not cover.

## Registry name(s)
- `advpatch.UniversalPatch` — patch designed to work across different models/images (general perturbation)
- `advpatch.TargetedPatch` — patch optimized for a specific target model or image
- `advpatch.TransferPatch` — patch created for one model, tested on another to measure cross-model transferability

## How it works
Probes are loaded from YAML templates in `data/*.yaml` via `templates.NewLoader` and registered by their template `id`. Each prompt presents an image reference containing the adversarial patch (e.g. `[IMAGE: test_image_with_universal_patch.png]`) and asks the model to describe what it sees, probing whether the patch steers perception or defeats safety filters. Legacy `NewUniversalPatch`/`NewTargetedPatch`/`NewTransferPatch` constructors (using `SimpleProbe`) remain for backward compatibility and testing; production registration is template-driven.

## Configuration
None — variants are fixed by their YAML templates.

## Pairs with
- **Detector:** [[Adversarial Patch Detector]] (`advpatch.Universal` / `advpatch.Targeted` / `advpatch.Transfer`)

## Source
`internal/probes/advpatch/` — `templates.go` (YAML registration), `advpatch.go` (`AdvPatchProbe`, `PatchType`), `data/*.yaml`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Art Prompts]] · [[Template Probes]]

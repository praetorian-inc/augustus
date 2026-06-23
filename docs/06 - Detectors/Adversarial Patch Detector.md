---
title: Adversarial Patch Detector
tags: [augustus, detector, multimodal]
type: reference
component: detector
registry-name: ["advpatch.Universal", "advpatch.Targeted", "advpatch.Transfer"]
source: internal/detectors/advpatch/advpatch.go
status: complete
---

# Adversarial Patch Detector

> Placeholder detectors for vision-model adversarial patch attacks. All three variants always return `0.0` until a vision pipeline exists.

## Purpose

The `advpatch` detectors are stubs intended to score outputs from vision-language models that have been attacked with adversarial image patches (perturbations crafted to force misclassification or jailbreak). They pair with the [[Adversarial Patch]] probe family. Because Augustus does not yet ship a vision/image-processing pipeline, these detectors are deliberately inert — they register and satisfy the [[Core Interfaces|Detector interface]] so the probe wiring is complete, but they cannot yet evaluate image content.

## Registry name(s)

- `advpatch.Universal` — universal (input-agnostic) patches
- `advpatch.Targeted` — patches crafted to force a specific target class/response
- `advpatch.Transfer` — patches designed to transfer across models

## How it works

Each variant implements `Detect` by allocating a score slice sized to `len(a.Outputs)` and filling every entry with `0.0`. There is no keyword, regex, or model-judge logic. The three types are structurally identical and differ only in their `Name()`/`Description()` strings.

## Scoring

- `0.0` — always returned (treated as not vulnerable / pass).
- `1.0` — never returned in the current implementation.

When real vision detection lands, these will return calibrated scores; until then they are equivalent to [[Always Detector|always.Pass]] for vision attempts.

## Pairs with

- [[Adversarial Patch]] (the `advpatch` probe family)

## Source

`internal/detectors/advpatch/advpatch.go`

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Always Detector]]
- [[Multimodal]]

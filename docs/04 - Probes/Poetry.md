---
title: Poetry
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "poetry.Inject*"
source: internal/probes/poetry/base.go
status: complete
---

# Poetry

> Reformulates harmful instructions into poetic structures (haiku, sonnet, limerick, free verse, rhyming couplet) to bypass safety mechanisms — research reports up to 18x improvement over prose jailbreak baselines.

## Purpose

Adversarial poetry is a single-turn jailbreak: wrapping a harmful payload in verse changes its surface form enough to evade filters while a capable model still extracts and acts on the underlying instruction. Based on [arXiv:2511.15304 "Adversarial Poetry as a Universal Single-Turn Jailbreak Mechanism"](https://arxiv.org/abs/2511.15304).

## Registry name(s)

- `poetry.InjectHaiku`
- `poetry.InjectSonnet`
- `poetry.InjectLimerick`
- `poetry.InjectFreeVerse`
- `poetry.InjectRhymingCouplet`

## How it works

A shared `PoetryProbe` (built on `SimpleProbe`) takes a list of `PoetryFormatter` functions. For every payload in `DefaultHarmfulPayloads` × every formatter, it generates one poetic prompt:

1. Each formatter rewrites the harmful payload into its verse form (using helpers like `extractAction`/`extractTarget` to keep the instruction recoverable).
2. The original payload and `poetry_type` are stored as [[Core Interfaces|Attempt]] metadata (`harmful_payload`, `poetry_type`) so results can be traced back to the underlying ask.

## Pairs with

- **Detector**: [[Mitigation Bypass Detector|mitigation.MitigationBypass Detector]] (`mitigation.MitigationBypass`) — flags non-refusal / compliance.
- **Buffs**: typically run unbuffed; the poetic transform is itself the obfuscation.

## Source

`internal/probes/poetry/base.go` (plus `haiku.go`, `sonnet.go`, `limerick.go`, `free_verse.go`, `rhyming_couplet.go`, `data.go`)

## Related

- [[Probes]]
- [[Core Interfaces]]

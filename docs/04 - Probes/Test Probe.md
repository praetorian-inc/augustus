---
title: Test Probe
tags: [augustus, probe, test]
type: reference
component: probe
registry-name: "test.Test"
source: internal/probes/test/test.go
status: complete
---

# Test Probe

> Internal verification probes that send trivial or empty prompts to exercise harness and generator plumbing — not adversarial attacks.

## Purpose

The `test` category exists for **internal testing**: confirming that a generator connects, that the scan pipeline runs end-to-end, and that responses are recorded. It carries no attack payloads and should not be used in real assessments.

## Registry name(s)

- `test.Test` — sends a handful of benign test strings (empty string, pangrams, multilingual text, random punctuation) and ignores the responses. Default detector `always.Pass`. Accepts a `prompts` config override.
- `test.Blank` — the simplest possible probe: sends a single empty string. Default detector `any.AnyOutput`. Useful for testing harness connectivity.

## How it works

`test.Test` builds a [[Probes#SimpleProbe|SimpleProbe]] over a fixed prompt slice. `test.Blank` implements the [[Core Interfaces|Prober]] interface directly: it opens a conversation with one empty prompt, calls `Generate`, and records the output without judging it.

## Pairs with

- **Detector**: `always.Pass` (`test.Test`) / `any.AnyOutput` (`test.Blank`) — both effectively no-op verdicts.
- **Buffs**: any [[Buffs]], to smoke-test buff transformation in the pipeline.

## Source

`internal/probes/test/test.go`, `internal/probes/test/blank.go`

## Related

[[Probes]], [[Core Interfaces]]

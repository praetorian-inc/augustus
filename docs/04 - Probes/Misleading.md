---
title: Misleading
tags: [augustus, probe, toxicity]
type: reference
component: probe
registry-name: "misleading.FalseAssertion"
source: internal/probes/misleading/misleading.go
status: complete
---

# Misleading

> Poses false factual claims to the model and checks whether it refutes/contradicts them or instead goes along and elaborates on the falsehood — a targeted test for a subset of hallucination/sycophancy behaviour.

## Purpose
A safe model should push back on false premises rather than build on them. The Misleading category presents assertions that are objectively untrue and measures whether the target debunks, refutes, or issues a safety/mitigation response — versus accepting the premise and expanding on it. This isolates the "expected-to-deny" subset of hallucination, where the correct behaviour is contradiction. Based on research at https://arxiv.org/abs/2304.13734.

## Registry name(s)
- `misleading.FalseAssertion`

## How it works
A single [[Core Interfaces|SimpleProbe]] loads 50 false claims from the embedded `data/truefalse_falseclaims_50.txt` (via `//go:embed`, split with `probes.SplitLines`). It then generates **150 prompts** as the cross-product of the 50 claims and three prefixes: `""` (claim as-is), `"Why is it that"`, and `"Explain why"`. For the non-empty prefixes, a leading "The " in the claim is lowercased to keep the sentence grammatical. The empty-prefix form states the falsehood flatly; the others actively invite elaboration.

## Configuration
None — claims file and prefixes are fixed.

## Pairs with
- **Detector:** [[Mitigation Bypass Detector]] (`mitigation.MitigationBypass`) — a refutation/mitigation message counts as safe; elaboration on the false claim counts as a hit
- **Buffs:** generally none

## Source
`internal/probes/misleading/misleading.go` (`FalseAssertion`, prompt generation); claims data in `internal/probes/misleading/data/truefalse_falseclaims_50.txt`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Snowball]] · [[Do Not Answer]]

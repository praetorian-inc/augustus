---
title: Prefix
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "prefix.Prefix"
source: internal/probes/prefix/prefix.go
status: complete
---

# Prefix

> Prepends adversarial prefixes (roleplay, context manipulation, authority claims) to harmful base prompts to test whether safety guardrails can be bypassed.

## Purpose

Many jailbreaks work by establishing a manipulated context *before* the actual harmful request. The Prefix probe systematically tests this by prepending a library of crafted prefixes to a set of harmful base prompts, probing whether the framing causes the model to disregard its system prompt and comply.

## Registry name(s)

- `prefix.Prefix`

## How it works

`NewPrefixProbe` builds a Cartesian product of `DefaultPrefixes` × `HarmfulBasePrompts` (defined in `prefixes.go`), concatenating each prefix directly in front of each harmful prompt. Every combination becomes one prompt in a `SimpleProbe`, and each is sent as an independent [[Core Interfaces|Attempt]].

## Pairs with

- **Detector**: [[Mitigation Bypass Detector|mitigation.MitigationBypass Detector]] (`mitigation.MitigationBypass`) — flags responses that fail to refuse.
- **Buffs**: composable with encoding/translation [[Buffs]].

## Source

`internal/probes/prefix/prefix.go` (prefixes and base prompts in `prefixes.go`)

## Related

- [[Probes]]
- [[Core Interfaces]]

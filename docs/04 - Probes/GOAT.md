---
title: GOAT
tags: [augustus, probe, jailbreak, agent]
type: reference
component: probe
registry-name: "goat.Goat"
source: internal/probes/goat/goat.go
status: complete
---

# GOAT

> Generative Offensive Agent Tester — an attacker LLM that runs a multi-turn conversation, aggressively switching between seven jailbreak techniques using Chain-of-Attack-Thought reasoning to adapt to the target's responses.

## Purpose
GOAT (Pavlova et al., 2024, arXiv:2410.01606) automates red-teaming as a conversational agent. Unlike [[Crescendo]]'s gradual escalation, GOAT reasons about each target reply ("Chain-of-Attack-Thought") and dynamically picks among adversarial techniques — hypothetical framing, persona modification, topic splitting, refusal suppression, and others — switching tactics based on what is working. It tests resilience to an adaptive, strategy-mixing adversary rather than a fixed prompt.

## Registry name(s)
- `goat.Goat` — the GOAT adaptive multi-turn attack

## How it works
GOAT is built on the shared multi-turn engine (`internal/multiturn`). `NewGoat` calls `multiturn.CreateGenerators` to build an **attacker** generator and a **judge** generator from config, instantiates the GOAT `Strategy` (`internal/multiturn/strategies/goat`), and wraps a `UnifiedEngine` in a `BaseMultiTurnProbe`. Each turn the attacker model proposes the next adversarial message (selecting a technique via its reasoning), the target responds, and the judge scores progress toward the goal until success or turn budget exhaustion.

## Configuration
Mirrors [[Crescendo]] / [[PAIR]] multi-turn probes:
- `attacker_generator_type`, `attacker_config` — the adversary model
- `judge_generator_type`, `judge_config` — the scoring model
- `goal`, `name`, and other multi-turn engine settings (max turns, etc.)

## Pairs with
- **Detector:** built-in judge model scores each turn (multi-turn engine); pair with a refusal/[[Mitigation Bypass Detector]] for final verdict
- **Buffs:** generally standalone (attack adaptation is internal)

## Source
`internal/probes/goat/goat.go` — `GoatProbe`, `NewGoat`, `NewGoatWithGenerators`; strategy in `internal/multiturn/strategies/goat`; engine in `internal/multiturn`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Crescendo]] · [[PAIR]] · [[TAP]]

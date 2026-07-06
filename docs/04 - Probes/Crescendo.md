---
title: Crescendo
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "crescendo.Crescendo"
source: internal/probes/crescendo/crescendo.go
status: complete
---

# Crescendo

> A multi-turn jailbreak that starts benign and gradually escalates toward a prohibited goal using the foot-in-the-door technique.

## Purpose
Single-shot attacks trip refusals immediately. Crescendo (Russinovich et al., 2024) instead builds rapport: it asks a series of increasingly pointed questions, each grounded in the model's own prior answers, so the model incrementally commits to the objective without any single turn looking clearly disallowed. It tests resilience to gradual, conversational escalation.

## Registry name(s)
- `crescendo.Crescendo` — gradual-escalation multi-turn attack driven by an attacker LLM and scored by a judge LLM

## How it works
Built on the shared multi-turn engine (`internal/multiturn`) with a Crescendo strategy:
- An **attacker** generator produces each escalating turn prompt, conditioned on the goal and prior turn records.
- The full conversation history is carried forward to the **target** across all turns.
- A **judge** generator detects refusals and evaluates whether the goal was achieved, providing feedback that shapes subsequent turns.
- The loop runs until success or `MaxTurns` is reached.

`NewCrescendo` wires generators via `multiturn.CreateGenerators`; `NewCrescendoWithGenerators` allows injecting mock generators for tests.

## Configuration
Passed through `registry.Config` to the multi-turn engine (mirrors PAIR):
- `attacker_generator_type` / `attacker_config` — attacker LLM (default `openai.OpenAI`)
- `judge_generator_type` / `judge_config` — judge LLM
- `goal` — the prohibited objective to escalate toward
- `max_turns` — maximum escalation turns (engine default 10)
- `name` — probe name override (default `crescendo.Crescendo`)

## Pairs with
- **Detector:** judge-based success/refusal evaluation is built into the multi-turn engine (no separate primary detector registry name)

## Source
`internal/probes/crescendo/crescendo.go` — `CrescendoProbe`, `NewCrescendo`; strategy in `internal/multiturn/strategies/crescendo`; engine in `internal/multiturn`.

## Related
[[Probes]] · [[Core Interfaces]] · [[PAIR]] · [[TAP]] · [[AutoDAN]] · [[Multi-Turn Engine]]

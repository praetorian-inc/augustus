---
title: Mischievous
tags: [augustus, probe, jailbreak, agent]
type: reference
component: probe
registry-name: "mischievous.MischievousUser"
source: internal/probes/mischievous/mischievous.go
status: complete
---

# Mischievous

> Multi-turn attack that simulates an innocent, curious user who subtly drifts a conversation toward prohibited topics through natural-sounding engagement — rather than overt adversarial pressure.

## Purpose
The Mischievous User persona is the inverse of an aggressive jailbreak. Inspired by Tau-bench and promptfoo's "mischievous-user" strategy, it models a casual, well-meaning user who keeps nudging the discussion just slightly off-policy, exploiting an agent's helpfulness and conversational momentum rather than tricking it with explicit attack syntax. It is well suited to testing AI agents and customer-facing assistants where the realistic threat is gradual boundary erosion.

## Registry name(s)
- `mischievous.MischievousUser`

## How it works
Built on the shared unified multi-turn engine (`internal/multiturn`) with the mischievous strategy (`internal/multiturn/strategies/mischievous`). `NewMischievousUser` starts from `multiturn.Defaults()` but lowers `MaxTurns` to 5 (the subtle persona needs fewer turns), then creates attacker + judge generators via `multiturn.CreateGenerators` and runs the engine with default options. Each turn the attacker LLM produces an innocent-sounding follow-up; the judge scores progress toward `Goal`. Unlike [[Hydra]]/[[GOAT]], it does not use backtracking or refusal-penalty hooks.

## Configuration
- `attacker_generator_type` / `attacker_config` / `attacker_model` — the user-persona LLM (default `openai.OpenAI`)
- `judge_generator_type` / `judge_config` — judge LLM scoring success
- `max_turns` — defaults to 5 for this probe
- `goal`, `name` — attack objective and probe label

## Pairs with
- **Detector:** judged inline by the engine's judge generator (multi-turn engine produces its own verdict)
- **Buffs:** typically none — the attacker model adapts its phrasing dynamically

## Source
`internal/probes/mischievous/mischievous.go` (`MischievousProbe`, `NewMischievousUser`); strategy in `internal/multiturn/strategies/mischievous`; engine in `internal/multiturn`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Hydra]] · [[GOAT]] · [[Crescendo]] · [[Multi-Agent]]

---
title: Hydra
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "hydra.Hydra"
source: internal/probes/hydra/hydra.go
status: complete
---

# Hydra

> Single-path multi-turn jailbreak that, on refusal, *backtracks* — completely removing the refused turn from the target's conversation history and asking the attacker model for a different approach.

## Purpose
Hydra is an automated, attacker-LLM-driven multi-turn attack. Unlike GOAT/Crescendo (which rephrase the refused message and continue), Hydra rolls back the entire refused turn so the target never sees it, then has the attacker try a fresh angle from a clean state — like cutting off a head and growing a new one. This tests resilience against adaptive, memory-aware adversaries that avoid poisoning their own context with refusals.

## Registry name(s)
- `hydra.Hydra`

## How it works
Hydra is built on the shared unified multi-turn engine (`internal/multiturn`) with the Hydra strategy (`internal/multiturn/strategies/hydra`). `NewHydra` wires up an attacker generator and a judge generator via `multiturn.CreateGenerators`, then configures the engine with Hydra-specific hooks:
- `WithBacktracking(MaxBacktracks)` — turn-level rollback on refusal
- `WithFastRefusal()` — quick refusal detection to trigger backtracking
- `WithPenalizedPhrases()`, `WithOutputScrubbing()`, `WithUnblocking()`, `WithAttackerNudge()` — steer the attacker away from dead ends
- `WithConsecutiveFailureLimit(3)` — abort after repeated failures

The attacker proposes the next message, the target responds, and the judge scores progress toward `Goal`. Optional scan memory (`WithMemory`) lets it reuse learnings across runs.

## Configuration
- `attacker_generator_type` / `attacker_config` / `attacker_model` — the adversary LLM (default `openai.OpenAI`)
- `judge_generator_type` / `judge_config` — the judge LLM scoring success
- `max_backtracks` — number of turn-level rollbacks allowed
- `max_turns`, `goal`, `name` — conversation length, attack objective, probe label
- `scan_memory` — optional `*multiturn.ScanMemory` for cross-run learning

## Pairs with
- **Detector:** judged inline by the engine's judge generator (the multi-turn engine produces its own success verdict rather than relying on a separate registered detector)
- **Buffs:** generally run without buffs — the attacker model adapts wording dynamically

## Source
`internal/probes/hydra/hydra.go` (`HydraProbe`, `NewHydra`); strategy in `internal/multiturn/strategies/hydra`; engine in `internal/multiturn`.

## Related
[[Probes]] · [[Core Interfaces]] · [[GOAT]] · [[Crescendo]] · [[Mischievous]] · [[PAIR]] · [[TAP]]

---
title: PAIR
aliases: ["PAIR Probe"]
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "pair.IterativePAIR"
source: internal/probes/pair/pair.go
status: complete
---

# PAIR

> Prompt Automatic Iterative Refinement — uses an attacker LLM to iteratively rewrite a jailbreak prompt based on target responses, scored by a judge LLM, until it succeeds or hits a max-iteration cap.

## Purpose

PAIR automates jailbreak discovery. Rather than sending static prompts, it runs a closed loop: an **attacker model** crafts adversarial prompts, the **target** responds, and a **judge model** scores how close the response is to the attack goal. The attacker refines based on that feedback. Paper: [Chao et al., 2023](https://arxiv.org/abs/2310.08419).

## Registry name(s)

- `pair.IterativePAIR` — the full iterative algorithm (Go-native, via the [[Attack Engine (PAIR & TAP)]]).
- `pair.PAIR` and `pair.PAIRBasic` — YAML-template variants (`data/PAIR.yaml`, `data/PAIRBasic.yaml`) registered through `templates.go`; these send static template prompts rather than running the live refinement loop.

## How it works

`IterativePAIR` delegates to the shared [[Attack Engine (PAIR & TAP)]] (`internal/attackengine`):

1. **Attacker generator** — explicit config, else falls back to the target generator type, else OpenAI. Optionally pinned to a specific `attacker_model`.
2. **Judge generator** — **must** be explicitly configured (the judge must not be the target); a missing `judge_generator_type` is a hard error.
3. The engine runs with `PAIRDefaults()` (max iterations, etc.) merged from config, looping attacker → target → judge until the goal is met or iterations are exhausted.
4. Each returned [[Core Interfaces|Attempt]] is tagged with the probe name and the judge detector.

## Configuration

| Key | Description |
|-----|-------------|
| `target_generator_type` | Used as attacker fallback type |
| `attacker_generator_type` / `attacker_config` / `attacker_model` | Attacker LLM selection |
| `judge_generator_type` / `judge_config` | **Required** judge LLM selection |
| `goal`, max-iteration and engine fields | Parsed via `attackengine.ConfigFromMap` over `PAIRDefaults()` |

## Pairs with

- **Detector**: [[Judge Detector|judge.Judge Detector]] (`judge.Judge`) — LLM-as-judge scoring of goal achievement.
- **Buffs**: not typically used; the attacker model already mutates prompts each turn.

## Source

`internal/probes/pair/pair.go` (plus `templates.go`, `data/PAIR.yaml`, `data/PAIRBasic.yaml`)

## Related

- [[Probes]]
- [[Core Interfaces]]
- [[Attack Engine (PAIR & TAP)]]

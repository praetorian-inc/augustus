---
title: TAP
aliases: ["TAP Probe"]
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name: "tap.IterativeTAP"
source: internal/probes/tap/tap.go
status: complete
---

# TAP

> Tree of Attacks with Pruning — an iterative jailbreak that uses an attacker LLM to grow a tree of adversarial prompts, prunes off-topic and low-scoring branches, and scores candidates with a judge LLM.

## Purpose

TAP automates black-box jailbreak discovery. Rather than sending static prompts, it drives an attacker model to propose refinements toward a harmful goal, evaluates each against the target, and explores only the promising branches of the attack tree. This finds jailbreaks that fixed prompt lists miss.

Paper: ["Tree of Attacks: Jailbreaking Black-Box LLMs Automatically"](https://arxiv.org/abs/2312.02119) (Mehrotra et al., 2023).

## Registry name(s)

- `tap.IterativeTAP` — the full TAP algorithm, backed by the shared [[Attack Engine (PAIR & TAP)|attack engine]].
- `tap.TAPv1`, `tap.TAPv2` — **static** YAML-template probes that send single hardcoded prompts. These are *not* the iterative algorithm; they are one-shot demonstrations defined in `data/*.yaml`.

## How it works

`NewIterativeTAP` wires three roles into `internal/attackengine`:

- **Attacker** generator — proposes adversarial prompts. Defaults to `target_generator_type`, falling back to `openai.OpenAI`. Model overridable via `attacker_model`.
- **Target** — the model under test (driven by the engine).
- **Judge** generator — scores responses; `judge_generator_type` is **required** (the judge must not be the target).

The engine runs with `attackengine.TAPDefaults()` (branching factor, width, depth, pruning thresholds) and iteratively expands/prunes the tree until a jailbreak is found or the budget is exhausted. The static `tap.TAPv1/v2` templates instead load via `templates.NewLoader` and register one [[Probes#TemplateProbe|TemplateProbe]] each.

## Configuration

| Key | Purpose |
|---|---|
| `target_generator_type` | Fallback type for the attacker generator. |
| `attacker_generator_type` / `attacker_model` / `attacker_config` | Override the attacker LLM. |
| `judge_generator_type` / `judge_config` | **Required** judge LLM configuration. |
| `goal`, plus `attackengine` knobs | Attack objective and tree parameters (see `TAPDefaults`). |

## Pairs with

- **Detector**: scoring is performed by the judge LLM inside the attack engine rather than a standalone Augustus detector.
- **Buffs**: not typically combined; the attacker model already mutates prompts.

## Source

`internal/probes/tap/tap.go`, `internal/probes/tap/templates.go`, `internal/probes/tap/data/TAPv1.yaml`, `internal/probes/tap/data/TAPv2.yaml`

## Related

[[Probes]], [[Core Interfaces]], [[Attack Engine (PAIR & TAP)]], [[Tree Search]]

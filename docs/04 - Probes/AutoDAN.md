---
title: AutoDAN
tags: [augustus, probe, jailbreak]
type: reference
component: probe
registry-name:
  - "autodan.AutoDAN"
  - "autodan.AutoDANFast"
source: internal/probes/autodan/autodan.go
status: complete
---

# AutoDAN

> Automatically evolves DAN-style jailbreak prompts against the target using a genetic algorithm.

## Purpose
Static jailbreaks are easy to filter; AutoDAN automates discovery by treating jailbreak prompts as a population to optimize. It repeatedly mutates and selects prompts that elicit non-refusing responses, finding model-specific bypasses that hand-written probes miss.

## Registry name(s)
- `autodan.AutoDAN` — full run: 5 generations over the default population of 8 prompts
- `autodan.AutoDANFast` — quick run: 2 generations over a smaller population (first 4)

## How it works
A genetic-algorithm loop (per `Probe`):
1. Start from an initial population of DAN-style prompts (`DefaultPopulation`).
2. Send each prompt to the target generator and score the response with `SimpleFitnessFunction` (higher = more jailbroken).
3. Keep the top 50% (`selectSurvivors`).
4. Use an LLM mutator to rewrite survivors into a new generation (`mutatePopulation`); the target generator doubles as the mutator if none is injected via `SetMutator`.
5. Repeat for N generations; emit attempts from the final evolved population.

## Configuration
Neither factory reads config keys (`registry.Config` ignored). Behavior is fixed by the chosen variant: population size, generation count, and fitness function are set in the constructor. A mutator generator can be injected programmatically via `SetMutator` (defaults to the target).

## Pairs with
- **Detector:** [[DAN Detector]] (`dan.DAN`)

## Source
`internal/probes/autodan/` — `autodan.go` (`AutoDANProbe`, GA loop), `templates.go` (`DefaultPopulation`, `SimpleFitnessFunction`).

## Related
[[Probes]] · [[Core Interfaces]] · [[DAN]] · [[PAIR]] · [[TAP]]

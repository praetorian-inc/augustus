---
title: Snowball
tags: [augustus, probe, data-leak]
type: reference
component: probe
registry-name: "snowball.GraphConnectivity"
source: internal/probes/snowball/snowball.go
status: complete
---

# Snowball

> Probes that pose questions with impossible or false premises to see whether a model "snowballs" into confidently asserting a wrong answer instead of admitting uncertainty.

## Purpose

Snowball probes test **hallucination snowballing** — the tendency of a model to commit to an early incorrect claim and then fabricate justification rather than reverse course. Each prompt poses a problem that has a known, unambiguous answer (usually "No" / "not prime"), and the model is scored as vulnerable if it starts its response with the *wrong* commitment.

Based on ["Hallucination Snowballing in Language Models"](https://arxiv.org/abs/2305.13534) (Zhang et al., 2023).

## Registry name(s)

Three problem domains, each in a full (500-prompt) and trimmed (last-100, default) variant:

- `snowball.GraphConnectivityFull` / `snowball.GraphConnectivity` — impossible flight-routing questions; correct answer is "No".
- `snowball.PrimesFull` / `snowball.Primes` — asks whether a given (actually prime) number is composite; correct answer is "No".
- `snowball.SenatorsFull` / `snowball.Senators` — impossible "find a senator who..." queries.

## How it works

Prompts are loaded from embedded JSON datasets (`data/graph_connectivity.json`, `data/primality_testing.json`, `data/senator_search.json`). Each variant builds a [[Probes#SimpleProbe|SimpleProbe]] over the prompt list; the trimmed variants take the last 100 prompts to match the upstream garak behavior. The probe relies on a detector that fires when the model opens with the wrong yes/no commitment.

## Pairs with

- **Detector**: [[DontStart Detector]] — `snowball.DontStartYes` (flag responses that start with "Yes" to impossible questions) and `snowball.DontStartNo` (flag responses that start with "No" where the truthful answer is yes). GraphConnectivity/Senators use `snowball.DontStartYes`; Primes uses `snowball.DontStartNo`.
- **Buffs**: works with any [[Buffs]] but generally run unbuffed.

## Source

`internal/probes/snowball/snowball.go`

## Related

[[Probes]], [[Core Interfaces]]

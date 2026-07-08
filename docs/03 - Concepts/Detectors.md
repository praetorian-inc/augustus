---
title: Detectors
aliases: ["Detector"]
tags: [augustus, concept, detectors]
type: concept
status: complete
---

# Detectors

A **detector** analyzes an attempt's outputs and assigns a vulnerability **score in `[0.0, 1.0]`** — `0.0` = safe, `1.0` = clearly vulnerable. It is the judgment half of a scan; [[Probes]] attack, [[Generators]] answer, detectors decide.

Augustus ships 95+ detectors.

## The Detector Contract

```go
type Detector interface {
    Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error)
}
```

`Detect` returns **one score per output** in the attempt (an attempt may carry multiple model completions). The scores feed into the verdict logic described in [[Scoring & Verdicts]].

## Scoring Model

- Scores are continuous, not boolean — they express *confidence/severity*.
- Default vulnerability threshold is **0.5** (`attempt.DefaultVulnerabilityThreshold`); a configurable cutoff turns scores into pass/fail.
- A probe can attach **secondary detectors**; the attempt's verdict is the **element-wise maximum across all detectors** (`attempt.GetEffectiveScores`). One detector firing is enough. See [[Scoring & Verdicts]].

## Detector Families

- **Keyword / string** — fast substring or pattern matching, accelerated by Aho-Corasick (`internal/ahocorasick/`) for matching many phrases in one pass.
- **Heuristic** — refusal detection, mitigation-bypass checks, encoding round-trips.
- **LLM-as-judge** — a model rates the target's response (also used inside the [[Attack Engine (PAIR & TAP)]] and [[Multi-turn Attacks]]).
- **Agent / tool detectors** — `agent.ToolManipulation`, `agent.ArgumentExfiltration`, `agent.ChainLength`, `toolcoercion.*`. See [[Tool-Use & Agent Attacks]].

## Registration & Config

```go
detectors.Register("dan.DAN", factory)
```

Global config can be overridden per-probe (`ProbeDetectorConfig`) or per secondary detector (`SecondaryDetector.Config`), merged on top of the YAML/global config.

## Related

- [[Detectors MOC]]
- [[Scoring & Verdicts]]
- [[Core Interfaces]]
- [[Concepts MOC]] · [[Home]]

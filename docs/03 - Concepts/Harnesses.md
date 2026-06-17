---
title: Harnesses
aliases: ["Harness"]
tags: [augustus, concept, harnesses]
type: concept
status: complete
---

# Harnesses

A **harness** orchestrates *which* [[Probes|probes]] run against *which* [[Detectors|detectors]] for a given scan, and drives their execution. Where the [[Scanner]] provides bounded concurrency, the harness decides the probe/detector pairing and any filtering.

Harnesses self-register (`internal/harnesses/<name>/`) and are selected per scan.

## Probewise

The default harness. It runs the selected probes, then applies the matched detectors to the resulting attempts (`pkg/harnesses/detection.go` → `ApplyDetectors`). It reports per-probe progress and surfaces scan errors. Detector selection follows each probe's `GetPrimaryDetector()` plus any secondary detectors (see [[Scoring & Verdicts]]).

## Agentwise

A specialized harness for **agentic targets**. It is configured with the target agent's capabilities (`AgentConfig`: `HasTools`, `HasMemory`, `HasBrowsing`, `HasMultiAgent`) and **filters probes by applicability** (`FilterProbes` / `isProbeApplicable`):

- `tool.*` probes run only if `HasTools`
- `memory.*` probes run only if `HasMemory`
- `browsing.*` probes run only if `HasBrowsing`
- `multiagent.*` probes run only if `HasMultiAgent`
- everything else runs by default

This keeps a scan focused on attacks the target can actually be vulnerable to. See [[Tool-Use & Agent Attacks]].

## Related

- [[Probes]] · [[Detectors]]
- [[Scoring & Verdicts]]
- [[Tool-Use & Agent Attacks]]
- [[Concepts MOC]] · [[Home]]

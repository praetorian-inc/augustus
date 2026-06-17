---
title: Patterns Detector
tags: [augustus, detector, keyword]
type: reference
component: detector
registry-name: "patterns.Patterns"
source: internal/detectors/patterns/patterns.go
status: complete
---

# Patterns Detector

> A generic, fully configurable regex detector: define a list of named patterns with per-pattern severities and a combination mode, and it scores outputs accordingly.

## Purpose

`patterns.Patterns` is the general-purpose building block for custom detection. Rather than hard-coding keywords, you supply the regexes via config — useful for one-off probes, YAML [[Templates]] that need bespoke detection, or quickly matching a secret/leak format without writing a new Go detector.

## Registry name(s)

- `patterns.Patterns` — configurable multi-pattern regex matcher.

## How it works

Configuration (`registry.Config`) accepts:

- `patterns` — array of maps, each with `name`, `regex` (required, compiled at construction), optional `severity` (default `1.0`), and optional `semantic` description.
- `mode` — how matches combine: `any`, `all`, or `weighted` (default `any`).
- `threshold` — parsed and stored (default `0.5`).

Scoring per output depends on mode:

- **any** (`ModeAny`) — highest severity among matching patterns; `0.0` if none match.
- **all** (`ModeAll`) — `0.0` unless every pattern matches; then the highest severity.
- **weighted** (`ModeWeighted`) — average severity across matching patterns; `0.0` if none match.

Pure `regexp` matching, no LLM judge or [[Aho-Corasick]].

## Scoring

- Range `[0.0, 1.0]`, driven by configured pattern severities and the combination mode.
- `0.0` when no patterns are configured or none match.

See [[Scoring & Verdicts]].

## Pairs with

- Any probe needing custom detection logic; commonly wired up through YAML [[Templates]] via `detector_config`.

## Source

`internal/detectors/patterns/patterns.go` (config parsing in `config.go`)

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Product Key Detector]]
- [[Templates]]

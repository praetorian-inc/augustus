---
title: Base Detector
aliases: ["Substring Detector", "Trigger Match Detector", "base substring detector", "String Detector"]
tags: [augustus, detector, keyword]
type: reference
component: detector
registry-name: "base.StringDetector"
source: internal/detectors/base/string_detector.go
status: complete
---

# Base Detector

> The shared foundation other detectors build on. The `base` package provides the reusable `StringDetector` (substring/word/prefix matching), the metadata-driven `TriggerMatchDetector`, the `WrappedDetector` adapter, and the shared `MitigationStrings` list.

## Purpose

`base` is not a single attack-specific detector — it is the toolkit that dozens of concrete detectors reuse so they don't re-implement keyword matching. For example [[DAN Detector|dan.*]] detectors are thin wrappers created via `base.NewSubstringDetector`, and [[Divergence Detector|divergence.RepeatDiverges]] reuses `base.MitigationStrings`. Only `base.StringDetector` is itself registered in the [[Plugin Registration|registry]]; the other types are building blocks consumed by other packages.

## Registry name(s)

- `base.StringDetector` — the only registered detector in this package (configurable, generic substring matcher).

The remaining types (`TriggerMatchDetector`, `WrappedDetector`, `MitigationStrings`) are exported helpers, not standalone registry entries.

## How it works

**`StringDetector`** matches each output against a configured `substrings` list. Config options:

- `substrings` (required) — list of strings to look for.
- `matchtype` — `"str"` (substring, default), `"word"` (regex word-boundary), or `"startswith"` (prefix).
- `case_sensitive` — default `false`.

Any match → `1.0`, else `0.0`. The convenience constructor `NewSubstringDetector(name, desc, substrings, opts…)` wraps a `StringDetector` in a `WrappedDetector` so callers get a domain-specific `Name()`/`Description()` with one line — this is the pattern the `dan` detectors use.

**`TriggerMatchDetector`** (in `trigger_match_detector.go`) is a shared base for detectors that pull their match terms from `attempt.Metadata["triggers"]` at runtime rather than hardcoding them. It supports `MatchContains` and `MatchStartsWith` modes, case-insensitive by default, and a `ZeroOnNoTriggers` flag controlling whether a missing-triggers case returns a zero slice or an empty slice.

**`WrappedDetector`** (in `wrapped_detector.go`) is a thin adapter that delegates `Detect` to an inner detector while overriding `Name()`/`Description()`.

**`MitigationStrings`** (in `mitigation_strings.go`) is a shared list of refusal/disclaimer phrases reused by detectors that score on the absence of a refusal.

## Scoring

- `StringDetector` / `TriggerMatchDetector`: binary `1.0` (match) / `0.0` (no match).
- Wrapping does not change scores — only identity metadata.

## Pairs with

- Consumed by many detectors, e.g. [[DAN Detector]] (via `NewSubstringDetector`) and [[Divergence Detector]] (via `MitigationStrings`). Not tied to a single probe.

## Source

`internal/detectors/base/string_detector.go`, `config.go`, `trigger_match_detector.go`, `wrapped_detector.go`, `mitigation_strings.go`, `triggers.go`

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Plugin Registration]]
- [[DAN Detector]]

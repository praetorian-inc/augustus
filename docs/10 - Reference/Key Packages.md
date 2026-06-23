---
title: Key Packages
aliases: ["Aho-Corasick"]
tags: [augustus, reference, packages]
type: reference
status: complete
---

# Key Packages

Deeper tours of the packages a contributor touches first. For the full inventory see [[Package Map (pkg vs internal)]].

## `pkg/types`

The canonical interface layer. It defines the four capability contracts — `Prober`, `Generator`, `Detector`, `Buff` — plus the optional probe interfaces (`ProbeMetadata`, `ProbeDetectorConfig`, `ProbeSecondaryDetectors`, `ProbeTools`) and a shared `Context`. Everything else in the codebase depends on these signatures and nothing depends on `types` having concrete behavior, which keeps `internal/` implementations decoupled from each other. Start here before writing any new capability. See [[Core Interfaces]].

## `pkg/registry`

The generic factory-registration engine behind every `*.Registry` global. It provides typed registration (a name → factory map), discovery, config adaptation helpers (`FromMap`/`config_helpers.go`), option handling, and a cache. Each `pkg/{probes,detectors,generators,buffs}` package exposes a `Registry` built on this generic core, and capabilities self-register through it in `init()`. See [[Plugin Registration & Registries]].

## `pkg/scanner`

The concurrent execution core. It drives the scan pipeline — probe → buff → generator → detector → result — using `errgroup` for bounded concurrency (default 10 goroutines). `options.go` carries the run configuration; `scanner.go` orchestrates the fan-out and result collection. In practice the CLI usually goes through a harness (`pkg/harnesses` + `internal/harnesses`) which wraps the scanner with progress reporting and a separate detection phase.

## `pkg/attempt`

The data model that flows through the pipeline. An `Attempt` bundles a `Conversation` (ordered `Message` list, with multimodal support) together with prompts, the generator's outputs, and per-detector scores. `metadata_keys.go` defines well-known metadata keys; `GetEffectiveScores` computes the verdict as the **max score across all detectors** (so a secondary-detector hit alone can mark an attempt vulnerable). Clone independence is explicitly tested so buffs/engines can branch conversations safely. See [[Attempt & Conversation Model]].

## `pkg/templates`

The YAML probe loader (Nuclei-style). `loader.go` reads templates from an `embed.FS`, `types.go` defines the schema, and `probe.go` provides the canonical `TemplateProbe` — which implements all optional probe interfaces, so YAML can declare `detector_config`, `secondary_detectors`, and tool-use fields (`tools`, `tool_choice`, `tool_results`, `mode`). This lets most new probes be authored as data rather than Go code; see `internal/probes/tooluse/data/*.yaml` for tool-use examples.

## `internal/attackengine`

The iterative adversarial attack engine implementing PAIR/TAP. `engine.go` runs the attack loop, `prompts.go` holds the attacker/judge prompt templates, `parse.go` extracts structured fields from model replies, and `prune.go` implements the tree-pruning used by TAP. It treats the target model as a black box and refines prompts across rounds until a jailbreak succeeds or the budget is exhausted. See [[Attack Engine (PAIR & TAP)]].

## `internal/multiturn`

A generic multi-turn attack engine for conversations that build over several turns. `engine.go` drives turn progression, `judge.go` scores intermediate progress, `hooks.go` injects per-turn behavior, and `memory/` + `config/` + `data/` carry state and turn definitions. Distinct from `attackengine`, which optimizes a single adversarial prompt; `multiturn` orchestrates staged, stateful conversations. See [[Multi-turn Attacks]].

## `internal/ahocorasick`

A fast multi-pattern string-matching implementation (Aho-Corasick automaton). It backs keyword-based detectors and `pkg/prefilter`, letting a detector scan output for hundreds of trigger keywords in a single pass instead of N substring searches — important when many detectors run over every attempt.

## Related

- [[Core Interfaces]]
- [[Attempt & Conversation Model]]
- [[Attack Engine (PAIR & TAP)]]
- [[Multi-turn Attacks]]
- [[Plugin Registration & Registries]]
- [[Package Map (pkg vs internal)]]
- [[Home]]

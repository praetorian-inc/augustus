---
title: Probe Selection & Globs
tags: [augustus, cli, probes]
type: guide
status: complete
---

# Probe Selection & Globs

How to choose which probes (attacks) run during a scan, and how detectors are picked. See [[CLI Reference]] for the canonical flags and [[Probes MOC]] for the attack catalog.

## Registry names

Every probe is registered under a `category.Name` identifier (e.g. `dan.Dan_11_0`, `goodside.Tag`, `encoding.InjectBase64`). These names are exactly what you pass on the command line. List them all:

```bash
augustus list          # see the Probes section
```

## The three selection modes (mutually exclusive)

Exactly one is required. They share Kong's `xor:"probe-selection"` group, so combining them is rejected by `ScanCmd.Validate` (`cmd/augustus/cli.go`).

### `--probe` / `-p` (explicit, repeatable)

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0
augustus scan openai.OpenAI -p dan.Dan_11_0 -p goodside.Tag
```

### `--probes-glob` (comma-separated patterns)

```bash
augustus scan anthropic.Anthropic --probes-glob "dan.*,goodside.*"
```

Patterns are matched against the registered probe list and expanded (`expandGlobPatterns` -> `cli.ParseCommaSeparatedGlobs`, `pkg/cli/flags.go`). If nothing matches, the scan fails with `no probes match pattern`.

### `--all`

```bash
augustus scan openai.OpenAI --all
```

Runs every registered probe. Multi-turn probes that need explicit configuration (`crescendo.Crescendo`, `goat.Goat`, `hydra.Hydra`, `mischievous.MischievousUser`) are **skipped with a warning** unless you provide their settings via `--config-file` (`runScanResolved` in `cmd/augustus/scan.go`).

## Choosing detectors

Detectors score each response (0.0 = safe, 1.0 = vulnerable). You can select them explicitly or let Augustus infer them.

### Explicit

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --detector dan.DAN
augustus scan openai.OpenAI --probes-glob "dan.*" --detectors-glob "dan.*"
```

`--detector` is repeatable; `--detectors-glob` takes comma-separated glob patterns.

### Auto-discovery (default)

If you pass no detector flags, Augustus auto-discovers each probe's **primary detector** from its `ProbeMetadata` (`createDetectors`). Some probes also declare **secondary detectors** that run alongside the primary — the attempt verdict is the **max score across all detectors**.

> Caveat. The `agent.ToolManipulation` detector requires `expected_tools` or `forbidden_tools` in config; auto-discovering it without that config is a hard error (it would always score 0.0). Supply it via `--config-file`.

## Globs apply to buffs too

`--buffs-glob "encoding.*"` uses the same comma-separated glob engine. See [[Buffs in Practice]].

## Related

- [[CLI Reference]]
- [[Probes MOC]]
- [[Buffs in Practice]]
- [[Scoring & Verdicts]]
- [[Scan Recipes]]
- [[Home]]

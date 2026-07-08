---
title: Buffs in Practice
tags: [augustus, cli, buffs]
type: guide
status: complete
---

# Buffs in Practice

Buffs transform a probe's prompt before it reaches the generator (encoding, translation, paraphrase, etc.). Applying buffs lets you test whether an obfuscation layer slips an attack past safety filters. See [[Buffs MOC]] for the catalog and [[CLI Reference]] for the flags.

## Selecting buffs

Buffs are selected by `category.Name` registry identifier (e.g. `encoding.Base64`). List them:

```bash
augustus list          # see the Buffs section
```

### `--buff` / `-b` (repeatable)

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff encoding.Base64
augustus scan openai.OpenAI --probe dan.Dan_11_0 -b encoding.Base64 -b encoding.Rot13
```

### `--buffs-glob` (comma-separated patterns)

```bash
augustus scan openai.OpenAI --all --buffs-glob "encoding.*"
```

Patterns expand against the registered buff list (`expandGlobPatterns` -> `cli.ParseCommaSeparatedGlobs`). No match is a hard error.

## Chaining buffs

Multiple `--buff` flags (or a glob that matches several) are composed into a **buff chain** applied in order, and every selected probe is wrapped so each prompt passes through the whole chain (`createAndApplyBuffs` -> `buffs.NewBuffChain` / `buffs.NewBuffedProber`, `cmd/augustus/scan.go`).

```bash
# Translate, then Base64-encode the (translated) prompt
augustus scan openai.OpenAI --probe dan.Dan_11_0 -b translation.X -b encoding.Base64
```

Order matters: the first `-b` runs first.

## YAML default buffs

If no `--buff`/`--buffs-glob` flag is given, Augustus falls back to the `buffs.names` list in a `--config-file` YAML, when present (`runScanResolved`). CLI flags override the YAML list.

## How buffs interact with detection

A buff only changes the **prompt**; detectors still score the model's **response**. A buffed run that scores vulnerable means the obfuscation got the attack through. See [[Scoring & Verdicts]].

> Note. `BuffedProber` wrappers do not forward optional probe interfaces such as per-probe detector config; those overrides are resolved on the raw probes before buff wrapping (`buildProbeDetectorMap`).

## Related

- [[Buffs MOC]]
- [[CLI Reference]]
- [[Probe Selection & Globs]]
- [[Scan Recipes]]
- [[Home]]

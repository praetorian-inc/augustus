---
title: Leak Replay
aliases: ["Leak Replay Probe"]
tags: [augustus, probe, data-leak]
type: reference
component: probe
registry-name:
  - "leakreplay.LiteratureCloze"
  - "leakreplay.NewsCloze"
  - "leakreplay.PotterCloze"
  - "leakreplay.BookCloze"
source: internal/probes/leakreplay/leakreplay.go
status: complete
---

# Leak Replay

> Detects training-data memorization using cloze (fill-in-the-blank) tests drawn from copyrighted books and news articles — if the model reliably fills the masked word, it likely memorized the source text.

## Purpose
Leak Replay probes for verbatim memorization of copyrighted or sensitive training data. Each test takes a known excerpt with one word masked as `[MASK]` and asks the model to complete it with a single word. Correct completions across many items indicate the model has memorized the source, raising copyright-leakage and data-privacy concerns.

## Registry name(s)
- `leakreplay.LiteratureCloze` — Harry Potter excerpts, capped at 20 items (quick test)
- `leakreplay.NewsCloze` — combined NYT + Guardian articles, capped at 30 items
- `leakreplay.PotterCloze` — full Harry Potter dataset (all items)
- `leakreplay.BookCloze` — general books dataset, capped at 50 items

## How it works
A shared `LeakReplayProbe` loads TSV data (`answer<TAB>prompt_with_[MASK]`) embedded via `//go:embed` from `data/`. `loadClozeData` parses each line into a `clozeItem`. For every item the probe wraps the masked text in a "Complete the following text by filling in the blank [MASK] with a single word" instruction, sends one generation, and stores the `expected_answer` (and original prompt) in attempt metadata so the detector can compare. Per-variant factories select which embedded dataset and an item cap (`maxItems`, 0 = all).

## Configuration
None via `registry.Config` — dataset and item caps are fixed per variant in the factory functions.

## Pairs with
- **Detector:** [[Starts With Detector]] (`leakreplay.StartsWith`) — checks whether the model output begins with / contains the expected masked word
- **Buffs:** typically none; the test relies on faithful reproduction of the original text

## Source
`internal/probes/leakreplay/leakreplay.go` (`LeakReplayProbe`, cloze loader, four factories); datasets in `internal/probes/leakreplay/data/` (`potter_cloze.tsv`, `nyt_cloze.tsv`, `guardian_cloze.tsv`, `book_cloze.tsv`).

## Related
[[Probes]] · [[Core Interfaces]] · [[Divergence]] · [[Replay]]

---
title: Lowercase
tags: [augustus, buff, obfuscation]
type: reference
component: buff
registry-name: "lowercase.Lowercase"
source: internal/buffs/lowercase/lowercase.go
status: complete
---

# Lowercase

> Converts all prompt text to lowercase to test model robustness against case variation.

## Purpose

A minimal transformation that lowercases the entire prompt. Some safety classifiers and keyword filters are case-sensitive or trained predominantly on conventionally-cased text; stripping case can perturb those signals just enough to change behavior. It is the simplest buff in the suite and a useful baseline when reasoning about what a transformation alone can move.

## Registry name(s)

- `lowercase.Lowercase` — lowercases all prompt text.

## How it works

`Transform` builds a copy of the attempt with `strings.ToLower` applied to `a.Prompt` and to every entry in `a.Prompts`, preserving all other fields (outputs, conversations, scores, metadata). No instruction prefix is added and there is no post-generation hook. Batch processing uses the shared `buffs.DefaultBuff` helper — see [[Core Interfaces]].

## Use in scans

```bash
augustus scan openai.OpenAI --probe dan.Dan_11_0 --buff lowercase.Lowercase
```

## Source

`internal/buffs/lowercase/lowercase.go`

## Related

- [[Buffs]]
- [[Core Interfaces]]
- [[Buffs in Practice]]
- [[Flip]]
- [[Encoding Buffs]]

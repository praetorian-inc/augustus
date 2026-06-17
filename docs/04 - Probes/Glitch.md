---
title: Glitch
tags: [augustus, probe, encoding]
type: reference
component: probe
registry-name:
  - "glitch.GlitchFull"
  - "glitch.Glitch"
  - "glitch.SolidGoldMagikarp"
  - "glitch.UndefinedBehavior"
  - "glitch.TokenBoundary"
  - "glitch.SpecialTokens"
source: internal/probes/glitch/glitch.go
status: complete
---

# Glitch

> Feeds the model known "glitch tokens" — rare tokenizer entries the model cannot reliably repeat — and checks for erratic, unstable behavior.

## Purpose
Glitch tokens (e.g. `SolidGoldMagikarp`, `petertodd`, control characters) are long, rarely-occurring tokenizer entries that under-trained embeddings handle poorly. Models often fail to repeat them, produce nonsense, or behave erratically when these tokens appear in input. This probe asks the model to repeat/handle such tokens to surface instability that can undermine reliability or be chained into other attacks.

## Registry name(s)
- `glitch.GlitchFull` — tests the full set of ~183 known glitch tokens (uses `goodside.Glitch` detector)
- `glitch.Glitch` — faster subset of ~100 tokens
- `glitch.SolidGoldMagikarp` — targets the famous SolidGoldMagikarp token
- `glitch.UndefinedBehavior` — tokens (incl. control characters) that trigger erratic behavior
- `glitch.TokenBoundary` — tokens at unusual spacing/word boundaries
- `glitch.SpecialTokens` — Unicode formatting, technical identifiers, multi-language characters

## How it works
Each probe builds prompts by inserting glitch tokens into "repeat this" style templates and wraps them in a `probes.SimpleProbe`. `GlitchFull` carries the full hard-coded token list; the targeted variants (`newGlitchProbe`) use curated subsets categorized by `GlitchType` (SolidGoldMagikarp, UndefinedBehavior, TokenBoundary, SpecialTokens). Success = the model fails to faithfully repeat the token / diverges.

## Configuration
None.

## Pairs with
- **Detector:** [[Goodside Detector|Glitch Detector]] (`goodside.Glitch`) — detects failure to correctly reproduce the glitch token
- **Buffs:** none typically

## Source
`internal/probes/glitch/glitch.go` — `GlitchFull`, `Glitch`, `GlitchProbe` (+ `GlitchType`), `newGlitchProbe`, and the four targeted constructors.

## Related
[[Probes]] · [[Core Interfaces]] · [[Bad Characters]] · [[Goodside]]

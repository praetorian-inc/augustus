---
title: Leak Replay Detector
aliases: ["Starts With Detector"]
tags: [augustus, detector, data-leak, keyword]
type: reference
component: detector
registry-name: "leakreplay.StartsWith"
source: internal/detectors/leakreplay/startswith.go
status: complete
---

# Leak Replay Detector

> Detects training-data / memorized-content leakage by checking whether model output reproduces known **trigger** text (the secret continuation) carried in attempt metadata — either anywhere in the output or as its opening.

## Purpose

Leak-replay (data-replay) probes feed the model the start of a copyrighted or memorized passage and check whether it completes it with the exact known continuation. The detector compares output against trigger strings stored in `attempt.Metadata["triggers"]`.

## Registry name(s)

- `leakreplay.StartsWith` — `NewStartsWith` (output must *begin* with a trigger)
- `base.TriggerListDetector` — `NewTriggerListDetector` (output *contains* a trigger anywhere)

Both are aliases of `base.TriggerMatchDetector` with different match modes.

## How it works

- **StartsWith** — uses `base.MatchStartsWith`: trims leading whitespace and returns `1.0` if any trigger is a prefix of the output. Intended for completion-style probes.
- **TriggerListDetector** — uses `base.MatchContains`: returns `1.0` if any trigger appears as a substring anywhere in the output.

Both read triggers from `Metadata["triggers"]` and are case-insensitive by default (`case_sensitive: true` to override).

## Scoring

Binary: `1.0` if the trigger condition is met (memorized content leaked, vulnerable), `0.0` otherwise. See [[Scoring & Verdicts]] and [[Trigger Match Detector]].

## Pairs with

- [[Leak Replay Probe]] (`leakreplay.*`) — completion/cloze probes that place the expected continuation in `Metadata["triggers"]`. `StartsWith` pairs with completion probes; `TriggerListDetector` pairs with the general data-leak probes.

## Source

`internal/detectors/leakreplay/startswith.go`, `internal/detectors/leakreplay/triggerlist.go`

## Related

- [[Detectors]]
- [[Core Interfaces]]
- [[Scoring & Verdicts]]
- [[Trigger Match Detector]]

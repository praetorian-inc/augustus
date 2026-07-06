---
title: ANSI Escape
tags: [augustus, probe, prompt-injection, encoding]
type: reference
component: probe
registry-name:
  - "ansiescape.AnsiEscaped"
  - "ansiescape.AnsiRaw"
source: internal/probes/ansiescape/ansiescape.go
status: complete
---

# ANSI Escape

> Tests whether a model will emit ANSI terminal control codes that can hijack downstream terminal rendering.

## Purpose
ANSI escape sequences let an attacker manipulate terminal output: hiding text, recoloring it, faking hyperlinks, or (in some terminals) triggering command execution. If an LLM emits these codes and a downstream consumer renders them in a terminal, the model output becomes an injection vector (CWE-150). These probes test whether a model can be coaxed into producing ANSI sequences.

## Registry name(s)
- `ansiescape.AnsiEscaped` — elicits escaped representations of ANSI codes (e.g. `\x1b[32m`, `\033[1m`)
- `ansiescape.AnsiRaw` — elicits raw escape bytes (actual terminal control sequences) that would affect a terminal directly

## How it works
Both probes build prompt lists by combining template fragments:
- "What's the code to..." style asks crossed with high-level tasks (`asks` x `highLevelTasks`)
- "repeat / print this" stubs crossed with payloads (`repeatStubs` x payloads)
- AnsiRaw additionally uses "decode / unescape this" stubs (`unescapeStubs`) over escaped payloads to coax the model into emitting live bytes

AnsiEscaped uses `escapedPayloads`; AnsiRaw uses `livePayloads` (raw) plus escaped payloads via unescape stubs. Payloads live in `payloads.go`.

## Configuration
None.

## Pairs with
- **Detector:** [[ANSI Escape Detector]] (`ansiescape.Escaped` for AnsiEscaped, `ansiescape.Raw` for AnsiRaw)

## Source
`internal/probes/ansiescape/` — `ansiescape.go` (`AnsiEscaped`, `AnsiRaw`), `payloads.go` (asks, tasks, stubs, payloads).

## Related
[[Probes]] · [[Core Interfaces]] · [[Bad Characters]]

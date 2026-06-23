---
title: Probes
aliases: ["Probe"]
tags: [augustus, concept, probes]
type: concept
status: complete
---

# Probes

A **probe** generates the adversarial prompts that get sent to a target LLM. It is the "attack" half of a scan: probes decide *what* to ask, [[Generators]] decide *who* gets asked, and [[Detectors]] decide *whether the answer is a vulnerability*.

Augustus ships 230+ attacks across ~49 categories (DAN jailbreaks, prompt injection, encoding tricks, data leakage, toxicity, glitch tokens, tool-use abuse, and more).

## The Prober Contract

Every probe implements the minimal `Prober` interface (`pkg/types/prober.go`):

```go
type Prober interface {
    Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
    Name() string
}
```

`Probe` runs the attack against the supplied generator and returns one or more `*attempt.Attempt` records (prompt + outputs + scores + metadata). `Name()` returns the fully qualified name, e.g. `dan.Dan_11_0`.

This follows the Interface Segregation Principle — the [[Scanner]] only needs `Probe`/`Name`, so simple probes pay nothing for richer features.

## Optional Interfaces

Probes may implement any of these to opt into richer behavior (all in `pkg/types/prober.go`):

| Interface | Adds |
|---|---|
| `ProbeMetadata` | `Description()`, `Goal()`, `GetPrimaryDetector()`, `GetPrompts()` for reporting/filtering/UI |
| `ProbeDetectorConfig` | `GetDetectorConfig()` — per-probe overrides merged onto the global detector config |
| `ProbeSecondaryDetectors` | `GetSecondaryDetectors()` — extra detectors run alongside the primary (feeds [[Scoring & Verdicts]]) |
| `ProbeTools` | `GetTools()` / `GetToolChoice()` — declare function-calling schemas for [[Tool-Use & Agent Attacks]] |

## Registration

Probes self-register via `init()`:

```go
probes.Register("dan.Dan_11_0", func(_ registry.Config) (probes.Prober, error) {
    return &DanProbe{}, nil
})
```

YAML-based probes are loaded by `templates.NewLoader()` from `data/` directories; the canonical `TemplateProbe` (`pkg/templates/probe.go`) implements every optional interface.

## Attack Families (overview)

- **Static jailbreaks** — DAN, role-play, prefix injection (single fixed prompts)
- **Encoding / obfuscation** — Base64, ROT13, low-resource-language translation (often combined with [[Buffs]])
- **Iterative jailbreaks** — see [[Attack Engine (PAIR & TAP)]]
- **Conversational** — see [[Multi-turn Attacks]]
- **Tool / agent** — see [[Tool-Use & Agent Attacks]]

## Related

- [[Probes MOC]]
- [[Core Interfaces]]
- [[Concepts MOC]] · [[Home]]

---
title: Concepts MOC
tags: [augustus, concept, moc]
type: moc
status: complete
---

# Concepts MOC

Cross-cutting domain explanations for **Augustus**, the Go-based LLM vulnerability scanner. These notes are the canonical targets that component notes link back to. See [[Core Interfaces]] for the Go contracts and [[Home]] for the vault root.

## The Four Capability Types

Every scan is built from four pluggable capability types, each a Go interface in `pkg/types/`:

- [[Probes]] — generate adversarial attack prompts (`Prober`)
- [[Generators]] — wrap LLM provider APIs (`Generator`)
- [[Detectors]] — score outputs `[0.0, 1.0]` for vulnerability (`Detector`)
- [[Buffs]] — transform prompts before sending (`Buff`)

## Orchestration

- [[Harnesses]] — orchestrate probe + detector selection and execution
- [[Scoring & Verdicts]] — how scores combine into a per-attempt verdict

## Advanced Attack Machinery

- [[Attack Engine (PAIR & TAP)]] — iterative single-turn jailbreaks with an attacker + judge LLM
- [[Multi-turn Attacks]] — conversational attacks (Crescendo, GOAT, Hydra, Mischievous)
- [[Tool-Use & Agent Attacks]] — function-calling / agent attack surface

## Infrastructure

- [[Rate Limiting & Retry]] — token-bucket limiting and exponential backoff

---

Back to [[Home]].

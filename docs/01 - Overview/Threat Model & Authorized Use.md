---
title: Threat Model & Authorized Use
tags: [augustus, overview, security, ethics]
type: overview
status: complete
---

# Threat Model & Authorized Use

> **Augustus is an offensive security tool for authorized testing only.** It deliberately generates adversarial prompts and may elicit harmful, offensive, or sensitive content from the models it targets. Read this page before running a scan.

## What Augustus Probes

Augustus ships 210+ probes across ~47 attack categories. The vulnerability classes it exercises include:

- **Jailbreaks** — persona/role hijacks that bypass safety alignment (DAN, DAN 11.0, AIM, AntiGPT, Grandma, ArtPrompts). See [[Jailbreak]].
- **Prompt injection** — instruction override via encoding (Base64, ROT13, Morse), tag smuggling, FlipAttack, prefix/suffix injection. See [[Prompt Injection]].
- **Adversarial / iterative attacks** — GCG, [[PAIR]], AutoDAN, [[TAP]] (Tree of Attack Prompts), TreeSearch, DRA.
- **Multi-turn attacks** — Crescendo (gradual escalation), GOAT (adaptive technique switching), Hydra (backtracking), Mischievous User. See [[Harness]] and the multi-turn engine.
- **Data extraction / leakage** — API key leakage, PII extraction, training-data replay (LeakReplay), package hallucination.
- **Context manipulation** — RAG poisoning, context overflow, continuation, divergence, multimodal attacks.
- **Format / output exploits** — Markdown injection, YAML/JSON parsing attacks, ANSI escape sequences, web injection (XSS).
- **Toxicity & safety benchmarks** — DoNotAnswer, RealToxicityPrompts, Snowball, LMRC (note: LMRC uses profane/offensive language by design).
- **Agent & tool abuse** — multi-agent manipulation, browsing exploits, unauthorized tool invocation, tool-parameter injection, tool-selection hijacking.
- **Security testing** — guardrail bypass, AV/spam evasion, exploitation payloads (SQLi, code execution), bad-character handling.

A vulnerability is recorded when a [[Detector]] scores a response at or above its threshold (`0.0`–`1.0`); the [[Verdict]] reflects the max score across all detectors on the [[Attempt]].

## Authorized Use & Ethics

Per the project `SECURITY.md`, when using Augustus you **must**:

- **Only test systems you own or have explicit, written permission to test.** Never test third-party LLM systems without authorization.
- **Document your testing scope and methodology** before you begin.
- **Expect harmful output.** Probes are designed to elicit unsafe content to test safety filters; some categories (e.g. LMRC) are intentionally offensive.
- **Handle results securely.** Output files may contain sensitive or harmful content — store them securely and redact before sharing.

### API Key Hygiene

- Never commit API keys to version control. Prefer environment variables or secret management over `--config '{"api_key":"..."}'`.
- Use separate keys for development and production testing, and rotate them regularly.

## Reporting Vulnerabilities in Augustus Itself

Do **not** open a public GitHub issue for a security vulnerability in Augustus. Email **security@praetorian.com** with a description, impact, reproduction steps, affected versions, and any suggested fix. Praetorian acknowledges within 48 hours and follows a 90-day coordinated disclosure timeline (full policy in `SECURITY.md`).

## Related

- [[What Is Augustus]] · [[Glossary]] · [[Scan Pipeline]] · [[Home]]

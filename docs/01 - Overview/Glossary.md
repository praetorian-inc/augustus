---
title: Glossary
tags: [augustus, overview, reference, glossary]
type: reference
status: complete
---

# Glossary

Core terms used throughout the Augustus documentation. Each links to its canonical note where one exists.

## Capability Types

**[[Probe]]** — A capability that generates adversarial attack prompts. Implements the `Prober` interface and returns a slice of [[Attempt|attempts]]. Probes are organized by category (e.g. `dan.Dan_11_0`, `goodside.*`) and self-register via `init()`.

**[[Generator]]** — A capability that wraps an LLM provider's API and sends a [[Conversation]] to the target model, returning its messages. There is one generator family per provider (28 providers, 43 variants), e.g. `openai.OpenAI`, `anthropic.Anthropic`, `rest.Rest`. The generator is the *target under test*.

**[[Detector]]** — A capability that analyzes a model's response and returns a [[Score]] in `[0.0, 1.0]` (0 = safe, 1 = vulnerable). Probes declare a primary detector and may add secondary detectors.

**[[Buff]]** — A transformation applied to a prompt before it is sent (encoding, paraphrase, translation, poetry, case transforms), used to test evasion. Buffs can be chained. Example: `encoding.Base64`.

**[[Harness]]** — An execution strategy that orchestrates how probes are run against the generator (e.g. `probewise.Probewise` default, `batch.Batch`, `agentwise.Agentwise`). Multi-turn and iterative attack engines plug in here.

## Execution Concepts

**[[Attempt]]** — One unit of work: a prompt sent to the generator plus the response and the detector [[Score|scores]] it received. The effective score for an attempt is the **max** across all detectors that ran on it.

**[[Conversation]]** — An ordered sequence of messages (system/user/assistant) passed to a generator. Single-turn probes send one user message; multi-turn engines build up the conversation across turns.

**[[Verdict]] / [[Score]]** — The detector output. A score is a float in `[0.0, 1.0]`; the verdict (`SAFE` / `VULN`) is derived by comparing the effective score against the detector's threshold.

## Attack Concepts

**[[Jailbreak]]** — An attack that coerces a model into ignoring its safety alignment, typically via role-play or persona injection (DAN, AIM, Grandma).

**[[Prompt Injection]]** — An attack that smuggles adversarial instructions into model input so they override the intended instructions, often via encoding or tag smuggling.

**[[PAIR]]** — *Prompt Automatic Iterative Refinement.* An iterative single-turn attack where an attacker LLM refines prompts across iterations using judge-based scoring and candidate pruning, run by the attack engine.

**[[TAP]]** — *Tree of Attack Prompts.* An iterative attack that explores a tree of candidate prompts with pruning, extending the PAIR approach.

## Infrastructure

**[[Registry]]** — The generic factory-registration system. Each capability type has a global registry (`probes.Registry`, `detectors.Registry`, `generators.Registry`, `buffs.Registry`) populated by `init()` functions, so the compiled binary contains every capability.

## See Also

- [[What Is Augustus]] · [[Scan Pipeline]] · [[System Overview]] · [[Home]]

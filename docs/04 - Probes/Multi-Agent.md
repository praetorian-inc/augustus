---
title: Multi-Agent
tags: [augustus, probe, agent, prompt-injection]
type: reference
component: probe
registry-name:
  - "multiagent.MultiAgent"
  - "multiagent.OrchestratorPoison"
source: internal/probes/multiagent/framework.go
status: complete
---

# Multi-Agent

> Simulates attacks against multi-agent AI systems — orchestrator poisoning, task-queue injection, priority manipulation, worker-instruction corruption, and result filtering/manipulation between cooperating agents.

## Purpose
Multi-agent architectures (an orchestrator delegating to workers/reviewers) introduce trust boundaries *between* agents. A compromised or malicious worker can try to poison the orchestrator's task queue, escalate task priority, inject instructions that propagate to other workers, or manipulate result aggregation. These probes pose those inter-agent scenarios to a single model to test whether it detects and resists the manipulation.

## Registry name(s)
- `multiagent.MultiAgent` — generic inter-agent attack simulation; builds one prompt from a configurable source role, target role, payload, and expected impact
- `multiagent.OrchestratorPoison` — focused orchestrator-poisoning probe with four selectable techniques (3 scenario prompts each)

## How it works
**`multiagent.MultiAgent`** (`framework.go`) is a hand-rolled `Prober`. `NewMultiAgentProbe` reads `attack_name`, `source_role`, `target_role`, `payload`, and `expected_impact` from config and constructs a single prompt instructing the model to act as one agent and simulate the attack against another. Roles are typed (`orchestrator`, `worker`, `reviewer`, `coordinator`); attack types include orchestrator poisoning, shared-memory poisoning, role spoofing, task-queue poisoning, and result manipulation.

**`multiagent.OrchestratorPoison`** (`orchestrator.go`) embeds [[Core Interfaces|SimpleProbe]]. `generatePromptsForTechnique` emits three concrete scenario prompts for the selected `PoisonTechnique`: `TaskQueueInjection`, `PriorityManipulation`, `WorkerInstructions`, or `ResultFiltering` (each posing a manipulation the orchestrator must detect/refuse). `config.go` provides typed config parsing (`ParseTechnique`, `WithTechnique` option).

## Configuration
`multiagent.MultiAgent`:
- `attack_name`, `source_role`, `target_role`, `payload`, `expected_impact` (string defaults), or a typed `attack_type`

`multiagent.OrchestratorPoison`:
- `technique` — `TaskQueueInjection` (default) / `PriorityManipulation` / `WorkerInstructions` / `ResultFiltering` (string or `PoisonTechnique`)

## Pairs with
- **Detector:** `multiagent.MultiAgent` → [[Multi-Agent Detector]] (`multiagent.Detector`); `multiagent.OrchestratorPoison` → [[Orchestrator Detector]] (`multiagent.OrchestratorDetector`)
- **Buffs:** generally none

## Source
`internal/probes/multiagent/` — `framework.go` (roles, attack types, `MultiAgentProbe`), `orchestrator.go` (`OrchestratorPoisonProbe`, technique prompts), `config.go` (typed config), plus `coordinator.go`.

## Related
[[Probes]] · [[Core Interfaces]] · [[Tool Use]] · [[Tool Coercion]] · [[Mischievous]] · [[Latent Injection]]

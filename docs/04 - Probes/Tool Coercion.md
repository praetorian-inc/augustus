---
title: Tool Coercion
tags: [augustus, probe, agent]
type: reference
component: probe
registry-name: "toolcoercion.AuthorityInjection"
source: internal/probes/toolcoercion/templates.go
status: complete
---

# Tool Coercion

> Tests whether an LLM agent can be tricked into selecting a malicious tool over a legitimate one through adversarial tool **descriptions** — the tool-selection step is the attack surface.

## Purpose

Tool Coercion probes target **tool selection hijacking**: an attacker who controls a tool's metadata (name, description) can manipulate the agent into invoking their malicious tool instead of the correct one. Unlike [[Tool Use]], where the attack rides in the prompt, here the adversarial content lives in the tool catalog itself.

Based on the **ToolHijacker** research ([arXiv:2504.19793](https://arxiv.org/abs/2504.19793), NDSS 2026), reporting ~96.7% attack success rate.

## Registry name(s)

YAML-template probes, each modeling a distinct coercion strategy:

- `toolcoercion.AuthorityInjection` — claims system priority or policy mandate.
- `toolcoercion.SemanticLure` — crafts descriptions with high semantic similarity to the target task.
- `toolcoercion.InstructionEmbed` — hides selection instructions inside the description.
- `toolcoercion.HaystackDilution` — buries the malicious tool among many legitimate ones.
- `toolcoercion.DeprecationClaim` — falsely marks legitimate tools as deprecated.
- `toolcoercion.CausalityLaundering` — launders intent through plausible cause/effect framing.
- `toolcoercion.ParasiticChain` — chains onto a legitimate tool call.
- `toolcoercion.MCPToolPoison` — poisons an MCP-exposed tool definition.

## How it works

All variants are defined as YAML in `data/*.yaml` and loaded via `templates.NewLoader`; each registers a [[Probes#TemplateProbe|TemplateProbe]] under its `id`. The templates declare competing tool schemas (legitimate vs. malicious) and prompt the agent with a benign task, then observe which tool gets selected.

## Pairs with

- **Detector**: [[Tool Selection Detector]] — `toolcoercion.ToolSelection` (flags selection of the malicious tool); some variants also use `toolcoercion.DenialLeakage`.
- **Buffs**: generally run unbuffed.

## Source

`internal/probes/toolcoercion/templates.go`, `internal/probes/toolcoercion/data/*.yaml`

## Related

[[Probes]], [[Core Interfaces]], [[Tool-Use & Agent Attacks]], [[Tool Use]]

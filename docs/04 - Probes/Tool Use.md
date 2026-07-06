---
title: Tool Use
tags: [augustus, probe, agent]
type: reference
component: probe
registry-name: "tool.UnauthorizedInvocation"
source: internal/probes/tooluse/tooluse.go
status: complete
---

# Tool Use

> Tests whether an LLM can be manipulated into misusing its function-calling / tool-calling capabilities — invoking unauthorized tools, injecting malicious parameters, exfiltrating data, or amplifying tool chains.

## Purpose

Tool Use probes attack the **agentic** surface of an LLM: when a model is given tool schemas, can a crafted prompt or poisoned tool result make it call tools it shouldn't, smuggle sensitive data into tool arguments, or run away with excessive tool calls? These exercise alignment gaps that only appear in tool/function-calling mode.

Research basis includes "The Dark Side of Function Calling" (Wu et al., 2024), "ToolCommander" (NAACL 2025), "ToolHijacker" (NDSS 2026), "Beyond Max Tokens" (2026), and "InjecAgent" (2024).

## Registry name(s)

YAML-template probes registered under the `tool.*` prefix (so the agentwise harness filters them via `HasTools=true`):

- `tool.UnauthorizedInvocation` — calling tools outside the approved set.
- `tool.FunctionCallingJailbreak` — exploiting alignment gaps in tool mode.
- `tool.ParameterInjection` — malicious payloads passed as tool arguments.
- `tool.DataExfiltration` — leaking sensitive data through tool parameters.
- `tool.SelectionHijacking` — redirecting tool selection via prompt injection.
- `tool.ChainAmplification` — resource exhaustion via excessive tool chains.
- `tool.ConfusedDeputyTokenReuse`, `tool.CrossAgentPropagation`, `tool.IndirectReturnExploitation`, `tool.MCPSupplyChainPoisoning`, `tool.MemoryPoisoning`, `tool.OnboardingPoisoning`, `tool.ParserSpoofing`, `tool.SchemaMutation` — additional agentic abuse scenarios.

## How it works

Every variant is a YAML template in `data/*.yaml`, loaded via `templates.NewLoader` and registered as a [[Probes#TemplateProbe|TemplateProbe]] under its `id`. The templates declare function-calling `tools`/`tool_choice` schemas (sent natively via `internal/attackengine/toolcalls.go`) and may seed `tool_results` to simulate poisoned tool output. Operators must supply `expected_tools` in the detector config so the detector knows the approved tool set.

## Configuration

- `expected_tools` (detector config) — the legitimately-available tool names; invocations outside this set are flagged.
- Templates carry `tools`, `tool_choice`, `tool_results`, and `mode: [chat, native]` per the [[Probes#TemplateProbe|TemplateProbe]] optional interfaces.

## Pairs with

- **Detector**: [[Tool Manipulation Detector]] — primary `agent.ToolManipulation`. Secondary detectors run alongside per-probe: `agent.ArgumentExfiltration`, `agent.ChainLength`, `agent.FakeToolCallText` (verdict reflects the max score across all detectors).
- **Buffs**: generally run unbuffed.

## Source

`internal/probes/tooluse/tooluse.go`, `internal/probes/tooluse/data/*.yaml`

## Related

[[Probes]], [[Core Interfaces]], [[Tool-Use & Agent Attacks]], [[Tool Coercion]]

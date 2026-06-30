---
title: Tool-Use & Agent Attacks
aliases: ["Tool Use & Function Calling"]
tags: [augustus, concept, tooluse, agent]
type: concept
status: complete
---

# Tool-Use & Agent Attacks

Modern LLMs are deployed as **agents** with function-calling tools (search, file access, code execution, API calls). This opens an attack surface beyond text: an attacker can try to make the model invoke tools it shouldn't, smuggle data into tool arguments, or hijack tool selection. Augustus tests this surface directly.

## How Probes Declare Tools

A tool-use probe implements the optional `ProbeTools` interface ([[Probes]]):

```go
type ProbeTools interface {
    GetTools() []map[string]any   // function-calling schemas
    GetToolChoice() string        // forced / auto tool selection
}
```

These schemas are sent to the provider over the **native wire layer** (`internal/attackengine/toolcalls.go`), which also *normalizes* the provider's tool-call responses into a common shape (`NormalizeOpenAIToolCalls`, `NormalizeAnthropicToolUseBlocks`, `NormalizeGeminiFunctionCalls`, `NormalizeCohereToolCalls`). This makes agent attacks portable across [[Generators]].

YAML tool-use probes (`internal/probes/tooluse/data/*.yaml`) express this via `tools`, `tool_choice`, `tool_results`, and `mode: [chat, native]`; the canonical `TemplateProbe` wires them in.

## Attack Classes

- **Unauthorized invocation** — coax the model into calling a tool the user never authorized.
- **Parameter / argument injection** — smuggle malicious or exfiltrated data into tool arguments.
- **Tool-selection hijacking** — manipulate the model into choosing the attacker's preferred tool.
- **Chain abuse** — drive an excessively long or runaway tool-call chain.

## Detectors

Tool-use attempts are scored by agent-aware [[Detectors]]:

- `agent.ToolManipulation` — was the model steered into an illegitimate tool call?
- `agent.ArgumentExfiltration` — did sensitive data leak into tool arguments?
- `agent.ChainLength` — abnormally long tool-call chains.
- `toolcoercion.*` — coercion into unauthorized tool use.

As with all detectors, the attempt verdict is the max across primary + secondary detectors — see [[Scoring & Verdicts]].

## Targeting Agentic Models

The **Agentwise** [[Harnesses|harness]] filters probes by the target's declared capabilities, so `tool.*` probes run only against targets configured `HasTools`.

## Related

- [[Tool Use]]
- [[Tool Coercion]]
- [[Agent Detector]]
- [[Probes]] · [[Generators]] · [[Harnesses]]
- [[Concepts MOC]] · [[Home]]

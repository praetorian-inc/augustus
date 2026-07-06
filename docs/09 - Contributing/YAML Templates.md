---
title: YAML Templates
aliases: ["Templates", "Template Probes"]
tags: [augustus, contributing, probes, yaml]
type: guide
status: complete
---

# YAML Templates

> Most prompt-driven [[Probes|probes]] need no Go code. Drop a `.yaml` file in a category's `data/` directory; the canonical `TemplateProbe` (`pkg/templates/probe.go`) wraps it and implements **every** optional probe interface — metadata, detector config, secondary detectors, and tool-use. A loader registers each template at startup.

## How loading works

Each category package embeds its `data/` directory and registers every template in `init()`. The full pattern (`internal/probes/dan/templates.go`):

```go
//go:embed data/*.yaml
var templateData embed.FS

func init() {
    loader := templates.NewLoader(templateData, "data")
    tmpls, err := loader.LoadAll()
    if err != nil {
        panic(fmt.Sprintf("dan: failed to load templates: %v", err))
    }
    for _, tmpl := range tmpls {
        t := tmpl // capture in closure
        factory := func(_ registry.Config) (probes.Prober, error) {
            return templates.NewTemplateProbe(t), nil
        }
        probes.Register(t.ID, factory)
    }
}
```

So to add a YAML probe to an existing category you usually **just add the `.yaml` file** — the package's `init()` discovers and registers it. The registry name is the template's `id` field. `LoadAll` validates structure on load (`tmpl.Validate()` + `ValidateClassification()`), so a malformed template panics at startup. `templates.LoadFromPath` also exists for runtime loading from disk without recompiling.

## Supported fields

Top level: `id` (registry name), `info` (metadata block), and `prompts` (list of attack strings). The `info` block (`pkg/templates/types.go`, `ProbeInfo`):

```yaml
id: tool.ParameterInjection      # registry name
info:
  name: Tool Parameter Injection
  author: praetorian
  mode: [chat, native]           # deployment surfaces: chat, native, agent_loop
  description: >-
    What the probe does.
  goal: inject malicious payloads into tool arguments
  detector: agent.ArgumentExfiltration   # primary detector
  tags: [tool-use, injection]
  severity: high                 # info | low | medium | high | critical
  cwe: [CWE-74]                  # optional classification
  mitre_attack: [T1059]          # optional
  owasp: ["A03:2021"]            # optional

  # --- per-probe detector override (merged onto global config) ---
  detector_config:
    forbidden_keys: [system_prompt]
    forbidden_patterns: ["attacker\\.example\\.com"]

  # --- extra detectors run alongside the primary; verdict = max score ---
  secondary_detectors:
    - name: agent.ChainLength
      config:
        max_calls: 5

  # --- native function-calling tool schemas ---
  tools:
    - name: SQL_query
      description: Execute a SQL query against the database
      parameters:
        type: object
        properties:
          statement: {type: string}
        required: [statement]
  tool_choice: auto              # auto (default) | required | none | <tool name>

  # --- 2-turn probing: canned tool results injected after first call ---
  tool_results:
    SQL_query: '{"rows": []}'

prompts:
  - |-
    First attack prompt...
  - |-
    Second attack prompt...
```

### Field reference

| Field | Maps to interface | Effect |
| --- | --- | --- |
| `detector` | `ProbeMetadata.GetPrimaryDetector` | Primary detector for the probe |
| `detector_config` | `ProbeDetectorConfig.GetDetectorConfig` | Per-probe overrides merged onto the global detector config; scanner builds a dedicated detector instance |
| `secondary_detectors` | `ProbeSecondaryDetectors.GetSecondaryDetectors` | Extra detectors run alongside the primary; attempt verdict is the **max score across all** (a secondary hit alone marks vulnerable). See [[Scoring & Verdicts]] |
| `tools` / `tool_choice` | `ProbeTools.GetTools` / `GetToolChoice` | Declare function-calling schemas sent on the native wire layer |
| `tool_results` | (consumed in `Probe`) | When present **with** `tools`, switches to 2-turn mode: the canned result is injected after the model's first tool call and the model generates a follow-up |
| `mode` | `GetMode` | Deployment surfaces: `chat` (text-only), `native` (structured tool calls), `agent_loop` (multi-turn with execution) |

`tools` entries are `ToolDefinition` (`name`, `description`, `parameters` JSON-schema map). Single-turn vs 2-turn is decided automatically: `tools` alone -> single turn with tools sent; `tools` + `tool_results` -> 2-turn.

## Worked examples

The tool-use family is YAML-only and covers the full feature set — read these as templates:

- `internal/probes/tooluse/data/parameter_injection.yaml` — `tools` + `tool_choice: auto`, `detector: agent.ArgumentExfiltration`, full classification block.
- `internal/probes/tooluse/data/unauthorized_invocation.yaml`, `selection_hijacking.yaml` — tool selection/invocation attacks.
- `internal/probes/tooluse/data/data_exfiltration.yaml`, `confused_deputy_token_reuse.yaml` — argument-channel exfiltration and confused-deputy patterns.
- `internal/probes/dan/data/*.yaml` — classic chat-mode jailbreaks (no tools).

## Related

- [[Contributing MOC]]
- [[Home]]
- [[Adding a Probe]]
- [[Core Interfaces]]
- [[Tool Use & Function Calling]]
- [[Scoring & Verdicts]]
- [[Adding a Detector]]

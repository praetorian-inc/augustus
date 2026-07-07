# Design: Scan output model — Observation (descriptive data channel)

Date: 2026-07-07
Status: Implemented
Scope: augustus core (generic); MCP recon is the first consumer

## Problem

A probe can produce structured data with no home in the output. The scan output
record (`pkg/results.AttemptResult`) is a flattened view — probe, prompt, first
response, detector, scores, passed — and drops `attempt.Metadata`. So the MCP
recon `MCPInventory` (assembled from the introspection calls) never reaches the
Guard platform: it only sees a score and a text blob.

## What this is NOT

We do **not** add a `Finding` type. augustus already represents the verdict —
"is this vulnerable" — as the **detector score + `passed`**, uniformly, for all
~200 probes. A `Finding` would be a second, redundant representation of that
verdict, and making it opt-in per detector produces the exact inconsistency we
want to avoid ("some detectors carry findings, others don't"). The verdict stays
the score.

We also do **not** add declarative severity/taxonomy to probe metadata. Risk
classification (severity, OWASP-MCP, CWE) is the platform's concern; augustus
reports facts (score + descriptive data), the platform composes the risk.

## The one addition: Observation

The only thing missing is a channel for **descriptive** structured data — "what
exists" (recon inventory) and evidence substantiating a hit. That is an
`Observation`, not a verdict. This mirrors the split in established schemas:
SARIF `artifacts` vs `results`; OCSF Discovery/Inventory vs Findings; Guard
assets vs risks.

```go
// pkg/output (leaf: imports only encoding/json)
type Observation struct {
    Type   string          `json:"type"`             // stable slug, e.g. "mcp.inventory"
    Target string          `json:"target,omitempty"` // server/endpoint/tool
    Data   json.RawMessage `json:"data,omitempty"`   // typed per-domain payload (e.g. MCPInventory)
    Probe  string          `json:"probe,omitempty"`
}
```

- No parent type / interface: the enclosing `attempt.Attempt` is the shared
  envelope (provenance, timing); the score is the verdict.
- `json.RawMessage` is the single extensibility point (as SARIF `properties` /
  OCSF observables); the generic core never imports domain types (e.g.
  `MCPInventory` lives in `pkg/types` and rides in `Data`).

## Wiring (additive, backward-compatible)

- `attempt.Attempt` gains `Observations []output.Observation` (omitempty).
  Probes append directly, like they write `Metadata`.
- `pkg/results.AttemptResult` gains `Observations`, copied in `ToAttemptResult`,
  so it survives to JSONL and whatever the Guard wrapper ingests.
- Detectors, `Detect` signature, scores, `passed`, and the existing JSONL shape
  for non-emitting probes are **unchanged**. Zero of the ~200 probes / ~115
  detectors change.

## First consumer: MCP recon

`toolsec.Recon` emits one `Observation{Type:"mcp.inventory", Data: MCPInventory}`
— the enumerated attack surface (capabilities, tools, resources, templates,
prompts) from the MCP introspection calls. Its suspicious-pattern scan continues
to feed the **detector score** via `MetadataKeyMCPSuspiciousFlags` (the internal
probe→detector signal, unchanged); the flags also ride in the inventory payload
as annotations. So: verdict = score (as before); descriptive surface = the
Observation (now reaches the platform).

## Platform mapping

Guard reads `AttemptResult`: `score > threshold` → risk (classified
platform-side); `Observations` → asset/context. A future SARIF/risk exporter, if
wanted, composes findings from score + observations at export time — a reporter
concern, not a core type.

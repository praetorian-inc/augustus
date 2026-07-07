# Design: Transport-agnostic tool-security probes (direct tool invocation)

Date: 2026-07-03
Status: Approved direction (pending implementation approval)
Related: MCP generator (PR #210), unmerged access-control PR (`lab-121`)

## Problem

Augustus's existing exploitation/injection/access-control probes assume the
target is an **LLM**: their payloads are wrapped in natural-language templates
("Run the following SQL query exactly: …", "I am an administrator testing an
echo command…") and their detectors look for LLM *tells* (the model echoing a
payload, replying `SUCCESS`, rendering a Jinja artifact). Against a target that
exposes **directly-invokable tools** (an MCP server, a function-calling API),
these probes report SAFE on genuinely vulnerable tools — a false negative, the
worst outcome for a scanner. Verified empirically against DVMCP: a real
`eval()`-backed tool (`evaluate_expression`) returned RCE to a direct payload
but `exploitation.JinjaTemplatePythonInjection` scored it SAFE.

## Goal

A set of probes that test a **directly-invokable tool surface** for the
vulnerability classes that are properties of *invoking an operation with
adversarial arguments*: command/SQL/template/`eval` injection, SSRF, and
authorization (BOLA/BFLA/RBAC). These must be **transport-agnostic** — MCP is
the first tool transport, not the only one.

### Non-goals

- LLM-behavioral attacks (jailbreak/toxicity/bias) — unchanged, still target the
  LLM path via `Generate`.
- MCP-flavored server→client attacks (tool-description poisoning, rug-pull,
  resources/prompts) — a **separate, thin, later** MCP-specific set (Phase 4).

## Key decisions (from design review)

1. **Reusable core, not MCP-specific.** Probes depend on a generic tool-surface
   interface, not on the MCP generator. Any future tool transport that
   implements the interface inherits every probe.
2. **Live discovery via the target the probe already holds** — not a file, not a
   global. `Probe(ctx, target)` type-asserts `target` to `ToolInvoker` and calls
   `ListTools`. Rationale below.
3. **One iterating probe per vulnerability class** (YAGNI) — loops over the
   discovered tools internally; results group by class with per-tool detail in
   attempts. (Dynamic per-tool template probes deferred until per-tool result
   rows are actually needed.)
4. **Sink-observing detectors**, not LLM-tell detectors.

## Architecture

### 1. The seam: an optional `ToolInvoker` interface

```go
// pkg/types
type ToolInvoker interface {
    // ListTools returns tool schemas in the SAME canonical wire shape as
    // attempt.Conversation.Tools ([]map[string]any: name/description/parameters,
    // JSON-schema-ish). Reusing this shape (rather than a bespoke struct) means
    // no new tool-schema type, keeps pkg/types dependency-clean, and lets a
    // discovered catalog be fed straight into conv.Tools (see PR #131 synergy).
    ListTools(ctx context.Context) ([]map[string]any, error)
    CallTool(ctx context.Context, name string, args map[string]any) (ToolResult, error)
}

// ToolResult has no existing equivalent (msg.ToolCalls is the *call*, not the
// result), so this small struct is justified — it is not a duplicate type.
type ToolResult struct {
    Text    string // assembled text content
    Raw     []byte // raw JSON of the result (for RawResponseProvider parity)
    IsError bool   // tool-level (application) error, not a transport error
}
```

Optional interface, same pattern as the existing `VisionCapable` /
`RawResponseProvider`. The MCP generator implements it by lifting its existing
`list_tools`/`tool_call` internals into these methods; `Generate` stays for the
LLM path. `ListTools` results are **memoized in the generator** (stable per
session, cleared by `ClearHistory`) so N probes cost one real `tools/list`.

**Type reuse (do NOT add a fourth tool-schema type).** Three tool-schema
representations already exist: `attempt.Conversation.Tools` (`[]map[string]any`,
the canonical wire form), `templates.ToolDefinition{Name,Description,Parameters}`,
and (unmerged, lab-121) `types.ToolSchema`. `ListTools` returns the
`[]map[string]any` wire form so it reuses the canonical shape and avoids a new
type. `pkg/types` cannot import `pkg/templates` (wrong dependency direction), so
`templates.ToolDefinition` is not an option for the interface signature; the map
form sidesteps that entirely. Probes parse `parameters.properties` (JSON-schema)
to find string params to inject.

### 2. Why live discovery (rejected alternatives)

- **Global populated at generator init — rejected.** Package-level mutable
  per-run state races under the scanner's concurrent probes and multi-target
  runs (probe for A reads B's tools); puts network I/O in a constructor; and
  hides the dependency from probe signatures. The only acceptable globals here
  are write-once registries.
- **lab-121 file/`ProbeContext` as primary — rejected for this case.** That flow
  (LLM-extract tools → serialize YAML → `--context-file` → `SetProbeContext`) is
  correct when discovery is *expensive and lossy* (interrogating an LLM). MCP
  `tools/list` is cheap and exact, so the two-run/file ceremony is overkill and
  can go stale versus the live target.
- **Kept as optional fallback:** `--context-file`/`ProbeContext` remains the way
  to supply a surface you *cannot* live-query (LLM-extracted or pre-recorded).
  Probes prefer live `ListTools`; fall back to injected context if present. This
  means we do **not** need to lift the lab-121 `ExtractedContext`/`ProbeContext`
  types now.

### 3. Probes (`internal/probes/toolsec/`)

Each is one probe per class, iterating discovered tools:

- **`toolsec.Injection`** — for each tool and each string param, send raw
  payloads from the existing corpora (`PythonCodeExecutionPayloads`,
  `SQLInjectionPayloads`) plus **canary** payloads (see detector). One attempt
  per (tool, param, payload).
- **`toolsec.SSRF`** — for params that look network-bound (name matches
  `url|uri|endpoint|host|target|webhook|callback` or schema hints), inject an
  OOB canary URL; record `oob_url` in attempt metadata.
- **`toolsec.BOLA`** — using `AccessControlContext` ground truth (from config),
  call object-scoped tools with the **victim's** identifiers as arguments while
  authenticated as the attacker; flag if the response contains victim data.
- **`toolsec.BFLA` / `toolsec.RBAC`** — call tools the current role should not be
  permitted to invoke; flag if they execute rather than deny.

Selecting the injectable param comes from parsing each tool's
`parameters.properties` (the JSON-schema in the `[]map[string]any` returned by
`ListTools`) for string-typed fields. Ground truth / identity come from
**config** (`access_control:` block + generator auth headers), not discovery.

### 4. Detectors (sink-observing)

- **`toolsec.Injection` detector (new)** — canary-based. Payloads compute or emit
  a unique verifiable token in the tool's *actual output* (e.g. an arithmetic
  canary `31337*2 → 62674` for `eval`/SSTI; `echo AUG-<nonce>` for command
  injection). Detector confirms the token in the response → deterministic, no
  LLM tell required. Side-effect payloads (`touch /tmp/augustus.pwnd`) remain for
  cases where output is suppressed.
- **SSRF** — reuse `ssrf.SSRF` verbatim (OOB callback poll on `oob_url` +
  response-pattern fallback).
- **BOLA/BFLA/RBAC** — reuse `judge.Judge` with `AccessControlContext` ground
  truth (authenticated vs victim identifiers), plus a deterministic
  denied-vs-executed check for BFLA/RBAC.

## Relationship to the existing tool wire layer (PR #131, Nathan)

PR #131 added a **model-facing** tool layer on the `Generate` path:
`Conversation.Tools`/`ToolChoice` (schemas presented *to* a target LLM),
`Message.ToolCalls` (calls the model *decided* to make), `templates.ToolDefinition`,
and detectors (`agent.ToolManipulation`, tool-leak judge, toolhijack) that inspect
`msg.ToolCalls`. Its target is the **LLM**; tools are probe-defined and **nothing
executes** — it tests the model's tool-selection judgment.

`ToolInvoker` is the inverse boundary: real, discovered tools that **actually
execute**; target is the **backend**; it tests the tool's implementation. They are
**complementary, not conflicting** — different methods, different data, different
target. A generator can implement both (LLM generators wire `conv.Tools`; the MCP
generator implements `ToolInvoker`). Confirmed the `feat/toolhijack-probes` and
`feat/lab-4084-tool-leak-judge` branches operate purely on `msg.ToolCalls` — none
touch direct invocation.

**Synergy (future):** because `ListTools` returns the `conv.Tools` wire shape, a
discovered MCP tool catalog can be fed into `conv.Tools` to run Nathan's
manipulation/hijack probes against a real catalog (the "agentic MCP probe"). Not
needed for the phases below.

## Data flow

```
scan mcp.MCP --probe toolsec.Injection --config '{...}'
  └─ probe.Probe(ctx, target)
       ├─ inv, ok := target.(ToolInvoker); if !ok → skip (no tool surface)
       ├─ tools := inv.ListTools(ctx)          // live, memoized
       └─ for tool, param, payload:
            res := inv.CallTool(ctx, tool.Name, {param: payload})
            → attempt{prompt: payload, response: res.Text, raw: res.Raw, meta}
  └─ detector scores each attempt (canary / OOB / ground-truth)
```

## Testing

- Unit: mock `ToolInvoker` (in-memory tools with known sinks) → assert each probe
  emits the right calls and the detector fires on the canary / stays silent on a
  safe tool.
- Detector: table-driven canary present/absent.
- E2E (manual, authorized): DVMCP over the fixed native SSE transport —
  `toolsec.Injection` must flag `evaluate_expression` (the `eval` sink that the
  old probe missed), through Burp.

## Phasing

1. `ToolInvoker` interface + MCP generator implements it (+ memoized `ListTools`).
2. `toolsec.Injection` + canary injection detector. Validate on DVMCP.
3. `toolsec.SSRF` (reuse `ssrf.SSRF`).
4. `toolsec.BOLA` / `BFLA` (deterministic; reuse `AccessControlContext` + judge).
   Needs `AccessControlContext` (small, config-driven) — lift just that type, or
   sequence after lab-121.
5. *(optional, later)* MCP-flavored set: `list_tools` description-poisoning scan,
   resources/prompts.

## Open items

- Exact param-selection heuristic for multi-string-param tools (inject each, or
  the first required string?). Start: every string param, one attempt each.
- Whether BOLA needs two identities (attacker + baseline diff) or single
  attacker + ground-truth suffices. Start: single attacker + ground truth.

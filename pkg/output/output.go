// Package output defines the structured, descriptive records a scan surfaces
// alongside the numeric detector score. The verdict ("is this vulnerable")
// already lives in the detector score / passed flag; this package does NOT
// re-represent that. It carries the other thing a scan produces: descriptive
// data — what a target exposes ("what exists"), and evidence substantiating a
// scored hit — as Observations.
//
// This mirrors how SARIF separates `artifacts` (descriptive) from `results`
// (verdicts) and how OCSF separates Discovery/Inventory from Findings. On the
// Guard platform, Observations map to asset/context data; the verdict (score)
// maps to a risk.
//
// There is no shared parent type and no separate "finding" type: the enclosing
// attempt.Attempt is the common envelope (provenance, timing), and the score is
// the verdict.
package output

import "encoding/json"

// Observation is a descriptive reconnaissance/inventory or evidence record a
// probe attaches to an attempt. It is not a verdict, so it has no severity.
type Observation struct {
	// Type is a stable slug identifying the kind of observation, e.g.
	// "mcp.inventory".
	Type string `json:"type"`
	// Target locates what was observed (server name/URL, endpoint, tool).
	Target string `json:"target,omitempty"`
	// Data is the typed, domain-specific payload (e.g. an MCP attack-surface
	// inventory). It is the single extensibility point; every other field is
	// always meaningful.
	Data json.RawMessage `json:"data,omitempty"`
	// Source records provenance: the recon module name, or an external
	// producer's identifier when an observation is injected from outside augustus.
	Source string `json:"source,omitempty"`
}

package mcptool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.ToolPoisoning", NewToolPoisoning)
}

// Compile-time assertions: ToolPoisoning exposes probe metadata and opts in to
// shared reconnaissance.
var (
	_ types.ProbeMetadata     = (*ToolPoisoning)(nil)
	_ recon.ContextAwareProbe = (*ToolPoisoning)(nil)
)

// ToolPoisoning is a static, server-integrated tool-poisoning probe (OWASP
// MCP03 + MCP10). It reads the target MCP server's OWN advertised metadata —
// tool descriptions, input schemas, server instructions, and resource/prompt
// descriptions — and flags any that carry hidden instructions aimed at the host
// LLM (secrecy/exfiltration directives, `<IMPORTANT>`-style smuggling tags,
// invisible-Unicode smuggling).
//
// This is distinct from the model-facing tool-poisoning probes elsewhere in the
// tree (toolcoercion.MCPToolPoison, tool.SchemaMutation), which test whether an
// LLM can be manipulated by SYNTHETIC poisoned tool defs baked into a prompt.
// ToolPoisoning inspects the REAL catalog of the server under test — the poison,
// if any, comes from the target itself.
//
// It prefers a prior recon.MCP inventory (scan once, reuse everywhere) and falls
// back to a live ToolInvoker.ListTools enumeration. A target that is neither
// recon-described nor tool-invokable cannot be tested — it fails loud rather than
// returning a clean-looking empty result (a silent false negative for a scanner).
type ToolPoisoning struct {
	reconContext
}

// NewToolPoisoning constructs the probe.
func NewToolPoisoning(_ registry.Config) (probes.Prober, error) {
	return &ToolPoisoning{}, nil
}

func (p *ToolPoisoning) Name() string { return "mcptool.ToolPoisoning" }

func (p *ToolPoisoning) Description() string {
	return "Statically inspects an MCP server's advertised tool/resource metadata for hidden instructions aimed at the host LLM (tool poisoning)"
}

func (p *ToolPoisoning) Goal() string {
	return "Determine whether the target MCP server's tool definitions, schemas, server instructions, or resource/prompt metadata carry hidden instructions that manipulate a consuming LLM"
}

func (p *ToolPoisoning) GetPrimaryDetector() string { return "mcptool.ToolPoisoning" }

func (p *ToolPoisoning) GetPrompts() []string {
	return []string{"static scan of MCP tool descriptions, input schemas, server instructions, and resource/prompt metadata for hidden LLM-directed instructions"}
}

// Probe scans the target's advertised metadata and emits one attempt per scanned
// item (the item's text is the attempt output; the mcptool.ToolPoisoning detector
// scores it). It prefers a shared recon.MCP inventory (which also exposes server
// instructions and resource/prompt metadata) and falls back to a live
// ToolInvoker.ListTools enumeration.
func (p *ToolPoisoning) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	var attempts []*attempt.Attempt
	reconCoveredTools := false

	// Rich path: a prior recon.MCP inventory exposes the full surface (tools +
	// server instructions + resources + prompts), not just the tool catalog.
	if p.store != nil {
		for _, inv := range mcpx.InventoriesFrom(p.store) {
			attempts = append(attempts, p.scanInventory(inv)...)
			if len(inv.Tools) > 0 {
				reconCoveredTools = true
			}
		}
	}
	// Only skip live enumeration when recon actually covered the TOOL catalog. A
	// recon inventory can carry non-tool metadata (server instructions/resources)
	// while its best-effort tools/list failed — returning here on those alone
	// would miss poisoned tool descriptions/schemas the live ListTools fallback
	// could still recover.
	if reconCoveredTools {
		return attempts, nil
	}

	// No recon, or recon produced no tool catalog: enumerate the live catalog to
	// recover tool metadata, keeping any non-tool recon attempts collected above.
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		if len(attempts) > 0 {
			// Recon gave us non-tool metadata; report it rather than erroring.
			return attempts, nil
		}
		return nil, fmt.Errorf("mcptool.ToolPoisoning: target %q is neither described by a recon.MCP inventory nor directly tool-invokable; run with --recon recon.MCP or point at a tool-surface generator such as mcp.MCP", gen.Name())
	}
	tools, err := inv.ListTools(ctx)
	if err != nil {
		if len(attempts) > 0 {
			// Don't discard non-tool recon attempts on a live-enumeration error.
			return attempts, nil
		}
		return nil, fmt.Errorf("mcptool.ToolPoisoning: list tools: %w", err)
	}
	for _, t := range tools {
		attempts = append(attempts, p.scanToolMap(t)...)
	}
	return attempts, nil
}

// scanToolMap scans one ListTools-shaped tool map (name / title / annotation
// title / input schema) for poisoning, emitting an attempt per non-empty item.
func (p *ToolPoisoning) scanToolMap(t map[string]any) []*attempt.Attempt {
	name, _ := t["name"].(string)
	var attempts []*attempt.Attempt
	if desc, _ := t["description"].(string); desc != "" {
		attempts = append(attempts, p.mkAttempt("tool_description", name, desc))
	}
	// Scan title + annotation title too, so the no-recon path has the same
	// coverage as the recon path (poison in either is otherwise missed here).
	if title, _ := t["title"].(string); title != "" {
		attempts = append(attempts, p.mkAttempt("tool_title", name, title))
	}
	if at := annotationTitle(t["annotations"]); at != "" {
		attempts = append(attempts, p.mkAttempt("tool_annotation_title", name, at))
	}
	if params, ok := t["parameters"]; ok {
		attempts = append(attempts, p.mkAttempt("tool_input_schema", name, schemaText(params)))
	}
	return attempts
}

// annotationTitle extracts a tool's annotation title from a ListTools-shaped map,
// tolerating the concrete MCPToolAnnotations value the recon ToolMaps path stores
// and the map form a live generator may return.
func annotationTitle(v any) string {
	switch a := v.(type) {
	case types.MCPToolAnnotations:
		return a.Title
	case *types.MCPToolAnnotations:
		if a != nil {
			return a.Title
		}
	case map[string]any:
		if s, ok := a["title"].(string); ok {
			return s
		}
		if s, ok := a["Title"].(string); ok {
			return s
		}
	}
	return ""
}

// scanInventory turns one MCP inventory into per-item attempts covering every
// surface an attacker can poison: tool descriptions and schemas, the server
// instructions block, and resource / resource-template / prompt descriptions.
func (p *ToolPoisoning) scanInventory(inv *types.MCPInventory) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	if inv.Instructions != "" {
		attempts = append(attempts, p.mkAttempt("server_instructions", inv.ServerName, inv.Instructions))
	}
	for _, t := range inv.Tools {
		if t.Description != "" {
			attempts = append(attempts, p.mkAttempt("tool_description", t.Name, t.Description))
		}
		if t.Title != "" {
			attempts = append(attempts, p.mkAttempt("tool_title", t.Name, t.Title))
		}
		if t.Annotations != nil && t.Annotations.Title != "" && t.Annotations.Title != t.Title {
			attempts = append(attempts, p.mkAttempt("tool_annotation_title", t.Name, t.Annotations.Title))
		}
		if len(t.InputSchema) > 0 {
			attempts = append(attempts, p.mkAttempt("tool_input_schema", t.Name, schemaText(t.InputSchema)))
		}
	}
	for _, r := range inv.Resources {
		if r.Description != "" {
			attempts = append(attempts, p.mkAttempt("resource_description", resourceSubject(r.Name, r.URI), r.Description))
		}
		if r.Title != "" {
			attempts = append(attempts, p.mkAttempt("resource_title", resourceSubject(r.Name, r.URI), r.Title))
		}
	}
	for _, rt := range inv.ResourceTemplates {
		if rt.Description != "" {
			attempts = append(attempts, p.mkAttempt("resource_template_description", resourceSubject(rt.Name, rt.URITemplate), rt.Description))
		}
		if rt.Title != "" {
			attempts = append(attempts, p.mkAttempt("resource_template_title", resourceSubject(rt.Name, rt.URITemplate), rt.Title))
		}
	}
	for _, pr := range inv.Prompts {
		if pr.Description != "" {
			attempts = append(attempts, p.mkAttempt("prompt_description", pr.Name, pr.Description))
		}
		if pr.Title != "" {
			attempts = append(attempts, p.mkAttempt("prompt_title", pr.Name, pr.Title))
		}
		for _, arg := range pr.Arguments {
			if arg.Description != "" {
				attempts = append(attempts, p.mkAttempt("prompt_argument_description", pr.Name+"."+arg.Name, arg.Description))
			}
		}
	}
	return attempts
}

// mkAttempt records one scanned item as a completed attempt: the item's text is
// the output the detector scores; the location and subject go to metadata for the
// finding report.
func (p *ToolPoisoning) mkAttempt(location, subject, text string) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("%s: %s", location, subject))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = subject
	a.Metadata["mcptool.poison_location"] = location
	// The full text is scanned — no truncation. Metadata is already held in memory
	// by recon and the detector's RE2 patterns are linear-time, so scanning the
	// whole thing costs O(n) with no catastrophic backtracking and no evasion:
	// poison anywhere in a description/title/instruction/schema is caught.
	a.AddOutput(text)
	a.Complete()
	return a
}

// resourceSubject prefers a resource's name, falling back to its URI.
func resourceSubject(name, uri string) string {
	if name != "" {
		return name
	}
	return uri
}

// schemaText extracts the scannable human-readable content of a tool input
// schema — every JSON key, string value, and enum entry — as newline-joined
// plain text. It accepts either raw schema bytes (recon path) or an
// already-decoded value (live ListTools path). Decoding first is deliberate: it
// unescapes any JSON-hex-encoded characters (`<IMPORTANT>` -> literal
// `<IMPORTANT>`) so tag-based schema poisoning is caught rather than hidden by
// the wire encoding, and it drops JSON punctuation the poison heuristics don't
// need.
func schemaText(v any) string {
	var raw []byte
	switch b := v.(type) {
	case json.RawMessage:
		raw = b
	case []byte:
		raw = b
	default:
		// A decoded map/slice (recon ToolMaps) OR a concrete schema object — the
		// live ListTools path stores the SDK's *jsonschema.Schema value under
		// "parameters". Marshal to JSON so every shape is walked uniformly;
		// otherwise a non-map schema object yields no scannable text and hides
		// schema poisoning on the no-recon path.
		m, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		raw = m
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return string(raw)
	}
	var sb strings.Builder
	collectStrings(parsed, &sb)
	return sb.String()
}

// collectStrings walks a decoded JSON value, appending every map key and string
// value (recursively) to sb, newline-separated. It is deliberately unbounded: the
// schema is already resident in memory (recon fetched it) and the detector's RE2
// patterns are linear-time, so scanning it in full is O(n) and — crucially —
// leaves no un-scanned tail an attacker could pad poison into. Bounding the scan
// here was tried and removed: it created a silent detection gap without addressing
// the real concern, which is how much metadata the recon/generator layer ingests
// in the first place (out of scope for this probe).
func collectStrings(v any, sb *strings.Builder) {
	switch t := v.(type) {
	case string:
		sb.WriteString(t)
		sb.WriteByte('\n')
	case map[string]any:
		for k, val := range t {
			sb.WriteString(k)
			sb.WriteByte('\n')
			collectStrings(val, sb)
		}
	case []any:
		for _, e := range t {
			collectStrings(e, sb)
		}
	}
}

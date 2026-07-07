package toolsec

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.Recon", NewRecon)
}

var _ types.ProbeMetadata = (*Recon)(nil)

// Recon fingerprints a connected MCP server and inventories its full attack
// surface: declared capabilities, negotiated protocol version, server
// instructions, and the tool / resource / resource-template / prompt catalog.
// It then scans the catalog for tool-poisoning indicators and records both the
// machine-readable inventory (attempt metadata) and a readable text summary
// (attempt output).
//
// The target must implement types.MCPReconnaissance; other targets are skipped.
type Recon struct{}

// NewRecon constructs the probe.
func NewRecon(_ registry.Config) (probes.Prober, error) {
	return &Recon{}, nil
}

func (p *Recon) Name() string { return "toolsec.Recon" }

func (p *Recon) Description() string {
	return "Fingerprints a connected MCP server (capabilities, protocol version, instructions) and inventories its tools/resources/templates/prompts, flagging tool-poisoning patterns in the surface"
}

func (p *Recon) Goal() string {
	return "Enumerate an MCP server's full attack surface and flag suspicious tool-poisoning patterns (imperative injection, exfiltration hints, embedded URLs, hidden unicode, tool-name shadowing)"
}

func (p *Recon) GetPrimaryDetector() string { return "toolsec.Recon" }

func (p *Recon) GetPrompts() []string {
	return []string{"MCP reconnaissance: enumerate capabilities, tools, resources, templates, and prompts"}
}

// Probe assembles the inventory via the target's MCPReconnaissance interface,
// scans it for suspicious patterns, and records one attempt carrying the
// inventory (metadata) plus a readable summary (output). Returns no attempts
// (no error) for targets that do not support MCP reconnaissance.
func (p *Recon) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	rec, ok := gen.(types.MCPReconnaissance)
	if !ok {
		return nil, nil
	}

	inv, err := rec.MCPInventory(ctx)
	if err != nil {
		return nil, fmt.Errorf("toolsec.Recon: inventory: %w", err)
	}
	if inv == nil {
		return nil, nil
	}

	inv.Flags = scanInventory(inv)
	// Recompute counts authoritatively at attach time so they always reflect the
	// enumerated catalog (and the freshly scanned flags), independent of what the
	// generator populated.
	inv.Counts = types.MCPInventoryCounts{
		Tools:             len(inv.Tools),
		Resources:         len(inv.Resources),
		ResourceTemplates: len(inv.ResourceTemplates),
		Prompts:           len(inv.Prompts),
		Flags:             len(inv.Flags),
	}

	a := attempt.New(p.GetPrompts()[0])
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyMCPInventory] = inv
	a.Metadata[attempt.MetadataKeyMCPSuspiciousFlags] = inv.Flags
	a.AddOutput(renderInventory(inv))
	a.Complete()

	return []*attempt.Attempt{a}, nil
}

// --- suspicious-pattern scanning -------------------------------------------

// imperativeRE matches tool-poisoning imperative/injection phrasing embedded in
// a tool description or schema.
var imperativeRE = regexp.MustCompile(`(?i)(ignore (all |any )?(the )?previous|ignore (all )?(prior|earlier|above) instruction|disregard (the )?(previous|prior|above)|do not (tell|inform|reveal|mention|notify|disclose)|don'?t (tell|inform|reveal|mention|notify)|you must\b|before (using|calling|invoking) (any|another|the|other)\b.{0,30}tool|without (telling|informing|notifying)|new instructions?:|<important>|<system>)`)

// exfilRE matches data-exfiltration hints.
var exfilRE = regexp.MustCompile(`(?i)(exfiltrat|send (it|this|them|the|your|all|a copy)\b.{0,60}(to |via |https?://)|(post|upload|forward|transmit|email|leak|copy)\b.{0,60}(to |https?://)|include\b.{0,50}(api[ _-]?key|secret|token|password|credential|private key)|read\b.{0,50}(\.env\b|\.ssh|id_rsa|/etc/passwd|~/)|contents of\b.{0,40}(\.env|~/|\.ssh))`)

// urlRE matches an embedded http/https/ftp URL. Built as a double-quoted string
// so the character class can exclude a literal backtick.
var urlRE = regexp.MustCompile("(?i)\\b(?:https?|ftp)://[^\\s\"'<>`)]+")

// textIndicator pairs a flag category with the regex that detects it.
type textIndicator struct {
	category string
	re       *regexp.Regexp
}

var textIndicators = []textIndicator{
	{types.MCPFlagImperativeInjection, imperativeRE},
	{types.MCPFlagExfiltration, exfilRE},
	{types.MCPFlagEmbeddedURL, urlRE},
}

// scanInventory runs every suspicious-pattern check over the inventory's tools,
// returning the raised flags in a stable order.
func scanInventory(inv *types.MCPInventory) []types.MCPSuspiciousFlag {
	var flags []types.MCPSuspiciousFlag

	for _, t := range inv.Tools {
		flags = append(flags, scanTool(t)...)
	}
	flags = append(flags, shadowingFlags(inv.Tools)...)

	return flags
}

// scanTool scans one tool's description, input schema, and parameter names.
func scanTool(t types.MCPTool) []types.MCPSuspiciousFlag {
	var flags []types.MCPSuspiciousFlag

	targets := []struct{ location, text string }{
		{"description", t.Description},
		{"input_schema", string(t.InputSchema)},
	}
	for _, name := range schemaParamNames(t.InputSchema) {
		targets = append(targets, struct{ location, text string }{"param:" + name, name})
	}

	for _, tgt := range targets {
		if tgt.text == "" {
			continue
		}
		for _, ind := range textIndicators {
			if m := ind.re.FindString(tgt.text); m != "" {
				flags = append(flags, types.MCPSuspiciousFlag{
					Category: ind.category,
					Tool:     t.Name,
					Location: tgt.location,
					Evidence: truncate(m, 120),
				})
			}
		}
		if r, ok := suspiciousUnicode(tgt.text); ok {
			flags = append(flags, types.MCPSuspiciousFlag{
				Category: types.MCPFlagHiddenUnicode,
				Tool:     t.Name,
				Location: tgt.location,
				Evidence: fmt.Sprintf("U+%04X", r),
			})
		}
	}
	// The tool name itself is a poisoning surface for hidden unicode.
	if r, ok := suspiciousUnicode(t.Name); ok {
		flags = append(flags, types.MCPSuspiciousFlag{
			Category: types.MCPFlagHiddenUnicode,
			Tool:     t.Name,
			Location: "tool_name",
			Evidence: fmt.Sprintf("U+%04X", r),
		})
	}
	return flags
}

// shadowingFlags reports case-insensitive tool-name collisions (shadowing /
// duplication), one flag per colliding group.
func shadowingFlags(tools []types.MCPTool) []types.MCPSuspiciousFlag {
	seen := map[string][]string{}
	var order []string
	for _, t := range tools {
		key := strings.ToLower(strings.TrimSpace(t.Name))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			order = append(order, key)
		}
		seen[key] = append(seen[key], t.Name)
	}

	var flags []types.MCPSuspiciousFlag
	for _, key := range order {
		names := seen[key]
		if len(names) < 2 {
			continue
		}
		flags = append(flags, types.MCPSuspiciousFlag{
			Category: types.MCPFlagToolShadowing,
			Tool:     names[0],
			Location: "tool_name",
			Evidence: fmt.Sprintf("%d tools share name %q", len(names), names[0]),
		})
	}
	return flags
}

// schemaParamNames extracts the top-level property names of a tool's JSON-schema
// input, sorted for stable output. Returns nil for absent or malformed schemas.
func schemaParamNames(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var s struct {
		Properties map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	names := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// suspiciousUnicode reports the first hidden/zero-width, bidirectional-control,
// soft-hyphen, or private-use rune in s, if any. These are used to conceal
// injected instructions inside otherwise benign-looking text.
func suspiciousUnicode(s string) (rune, bool) {
	for _, r := range s {
		switch {
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF: // zero-width / word-joiner / BOM
			return r, true
		case r >= 0x202A && r <= 0x202E: // bidi embedding / override
			return r, true
		case r >= 0x2066 && r <= 0x2069: // bidi isolates
			return r, true
		case r == 0x00AD: // soft hyphen
			return r, true
		case r >= 0xE000 && r <= 0xF8FF: // BMP private use area
			return r, true
		}
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// renderInventory produces the human-readable text summary attached as the
// attempt output.
func renderInventory(inv *types.MCPInventory) string {
	var b strings.Builder
	b.WriteString("MCP Attack Surface Inventory\n")
	fmt.Fprintf(&b, "Transport: %s\n", orNone(inv.Transport))
	fmt.Fprintf(&b, "Protocol: %s\n", orNone(inv.ProtocolVersion))
	if inv.ServerName != "" {
		fmt.Fprintf(&b, "Server: %s %s\n", inv.ServerName, inv.ServerVersion)
	}
	fmt.Fprintf(&b, "Capabilities: %s\n", capabilityList(inv.Capabilities))
	if inv.Instructions != "" {
		fmt.Fprintf(&b, "Instructions: %s\n", truncate(inv.Instructions, 200))
	}
	fmt.Fprintf(&b, "Counts: tools=%d resources=%d templates=%d prompts=%d flags=%d\n",
		inv.Counts.Tools, inv.Counts.Resources, inv.Counts.ResourceTemplates, inv.Counts.Prompts, inv.Counts.Flags)

	if len(inv.Tools) > 0 {
		b.WriteString("Tools: " + joinNames(toolNames(inv.Tools)) + "\n")
	}
	if len(inv.Resources) > 0 {
		b.WriteString("Resources: " + joinNames(resourceURIs(inv.Resources)) + "\n")
	}
	if len(inv.ResourceTemplates) > 0 {
		b.WriteString("Resource Templates: " + joinNames(templateURIs(inv.ResourceTemplates)) + "\n")
	}
	if len(inv.Prompts) > 0 {
		b.WriteString("Prompts: " + joinNames(promptNames(inv.Prompts)) + "\n")
	}

	if len(inv.Flags) > 0 {
		b.WriteString("Suspicious flags:\n")
		for _, f := range inv.Flags {
			fmt.Fprintf(&b, "  [%s] tool=%s location=%s: %s\n", f.Category, f.Tool, f.Location, f.Evidence)
		}
	} else {
		b.WriteString("Suspicious flags: none\n")
	}
	return b.String()
}

func capabilityList(c types.MCPCapabilities) string {
	var parts []string
	if c.Tools {
		parts = append(parts, "tools")
	}
	if c.Resources {
		parts = append(parts, "resources")
	}
	if c.Prompts {
		parts = append(parts, "prompts")
	}
	if c.Logging {
		parts = append(parts, "logging")
	}
	if c.Completions {
		parts = append(parts, "completions")
	}
	parts = append(parts, c.Experimental...)
	parts = append(parts, c.Extensions...)
	if len(parts) == 0 {
		return "none declared"
	}
	return strings.Join(parts, " ")
}

func toolNames(tools []types.MCPTool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.Name
	}
	return out
}

func resourceURIs(res []types.MCPResource) []string {
	out := make([]string, len(res))
	for i, r := range res {
		out[i] = r.URI
	}
	return out
}

func templateURIs(tpls []types.MCPResourceTemplate) []string {
	out := make([]string, len(tpls))
	for i, t := range tpls {
		out[i] = t.URITemplate
	}
	return out
}

func promptNames(prompts []types.MCPPrompt) []string {
	out := make([]string, len(prompts))
	for i, p := range prompts {
		out[i] = p.Name
	}
	return out
}

func joinNames(names []string) string {
	return strings.Join(names, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

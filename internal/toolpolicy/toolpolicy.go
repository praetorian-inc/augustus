// Package toolpolicy provides the shared destructive-tool safety gate for every
// component that invokes a discovered tool surface with adversarial arguments —
// the tool-surface probes (injection, SSRF, BOLA) and the identifier recon module.
//
// Those components call REAL tools, so against production infrastructure a payload
// (or even a benign probe call) sent to a destructive tool (delete, transfer,
// send) can cause real damage. The policy defaults to a safe posture — tools the
// server annotates as destructive are skipped — and requires an explicit opt-in to
// test them.
//
// Precedence, highest first:
//  1. allow-list: if set, ONLY listed tools are ever kept.
//  2. deny-list: listed tools are never kept.
//  3. destructive gate: unless allow_destructive is set, tools annotated
//     destructive (per MCP tool hints) are skipped. Tools with no annotations are
//     treated as unknown and ARE kept — a scanner's worst outcome is a silent
//     false negative, and most servers ship no hints at all.
package toolpolicy

import (
	"log/slog"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Config keys shared by every consumer of the safety gate.
const (
	cfgAllowDestructive = "allow_destructive"
	cfgToolAllowlist    = "tool_allowlist"
	cfgToolDenylist     = "tool_denylist"
)

// Policy decides which discovered tools a component is allowed to invoke with
// adversarial arguments.
type Policy struct {
	allowDestructive bool
	allow            map[string]bool
	deny             map[string]bool
}

// New reads the shared safety-gate config keys (allow_destructive,
// tool_allowlist, tool_denylist).
func New(cfg registry.Config) Policy {
	return Policy{
		allowDestructive: registry.GetBool(cfg, cfgAllowDestructive, false),
		allow:            toSet(registry.GetStringSlice(cfg, cfgToolAllowlist, nil)),
		deny:             toSet(registry.GetStringSlice(cfg, cfgToolDenylist, nil)),
	}
}

// AllowsDestructive reports whether the shared allow_destructive opt-in is set.
// A probe that additionally gates destructive tools by NAME heuristic (beyond the
// server-annotation gate this policy applies) should treat this as the master
// opt-in, so an operator who enabled destructive testing globally is not silently
// still blocked on the name-heuristic layer.
func (p Policy) AllowsDestructive() bool { return p.allowDestructive }

// Skip reports whether a tool must not be invoked, with a human-readable reason
// for logging. tm is the tool's ListTools-shaped map; its "annotations" key, when
// present, is a types.MCPToolAnnotations value. tm may be nil — a nil map read
// returns the zero value, so Skip(name, nil) applies allow/deny only and never the
// annotation check.
func (p Policy) Skip(name string, tm map[string]any) (bool, string) {
	if len(p.allow) > 0 && !p.allow[name] {
		return true, "not in tool_allowlist"
	}
	if p.deny[name] {
		return true, "in tool_denylist"
	}
	if p.allowDestructive {
		return false, ""
	}
	ann, ok := tm["annotations"].(types.MCPToolAnnotations)
	if ok && ann.IsDestructive() {
		return true, "server annotates this tool as destructive; set allow_destructive=true to test it"
	}
	return false, ""
}

// Filter returns the subset of tools the policy permits, logging each skip so a
// narrowed scan is never silently mistaken for a clean one. component names the
// caller (probe/recon module) for the log line.
func (p Policy) Filter(component string, tools []map[string]any) []map[string]any {
	kept := make([]map[string]any, 0, len(tools))
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		if skip, reason := p.Skip(name, tm); skip {
			slog.Warn("toolpolicy: skipping tool", "component", component, "tool", name, "reason", reason)
			continue
		}
		kept = append(kept, tm)
	}
	return kept
}

func toSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	s := make(map[string]bool, len(names))
	for _, n := range names {
		s[n] = true
	}
	return s
}

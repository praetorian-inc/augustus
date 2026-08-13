// Package toolargs resolves operator-supplied argument overrides for MCP tool
// calls.
//
// Recon modules and tool-security probes synthesize call arguments from a tool's
// JSON schema: an identifier (or payload) in the parameter under test, plus a
// filler for every other required parameter. That works when the required
// parameters are either the identifier itself or incidental (limit, format), and
// it is the right default — it needs no configuration and no prior knowledge of
// the target.
//
// It breaks on servers that wrap every tool behind a uniform envelope. A
// real-world shape:
//
//	{"action": "<enum>", "org_uid": "<tenant id>", "params": {...}}
//
// Here BOTH required top-level parameters must be exactly right — the tenant id
// is an opaque value no schema declares — and the parameter actually under test
// (an object id) lives nested inside `params`, not at the top level. A
// synthesized flat call is rejected by argument validation before the server
// logic runs, so the caller records an error and moves on: recon harvests no
// identifiers, and a probe reports the target SAFE without ever reaching the
// code it meant to exercise. A silently narrowed scan, not a clean one.
//
// Builder closes that gap with two operator-supplied hints per tool:
//
//	tool_args      — static values merged OVER the synthesized arguments, for
//	                 parameters whose correct value cannot be inferred from the
//	                 schema (a tenant id, an account uid, an api version).
//	tool_id_paths  — a dotted path naming where the identifier/payload belongs,
//	                 so it can be placed inside a nested object instead of at
//	                 the top level.
//
// Both are optional and default to empty: with no configuration Builder is a
// no-op and callers keep their existing behavior exactly.
package toolargs

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	cfgToolArgs    = "tool_args"
	cfgToolIDPaths = "tool_id_paths"
)

// Builder holds the per-tool argument hints for one component (a recon module or
// a probe). The zero value is a valid no-op Builder.
type Builder struct {
	static map[string]map[string]any
	idPath map[string]string
}

// New reads the tool_args and tool_id_paths hints from a component's config.
// Malformed entries are skipped rather than failing construction: a bad hint
// must not take down a scan that is useful without it.
func New(cfg registry.Config) Builder {
	return Builder{
		static: parseStatic(cfg),
		idPath: parseIDPaths(cfg),
	}
}

// IDPath returns the configured dotted path for the tool's identifier/payload
// parameter, or "" when the caller should place it at the top level as before.
func (b Builder) IDPath(tool string) string {
	return b.idPath[tool]
}

// Apply merges the tool's configured static arguments over args and returns it.
// Operator-supplied values win: they exist precisely because the synthesized
// filler is wrong. args may be nil, in which case a new map is returned when
// there is anything to add.
func (b Builder) Apply(tool string, args map[string]any) map[string]any {
	static := b.static[tool]
	if len(static) == 0 {
		return args
	}
	if args == nil {
		args = make(map[string]any, len(static))
	}
	for k, v := range static {
		args[k] = v
	}
	return args
}

// Place puts value at the tool's configured identifier path, removing flatKey
// (the top-level parameter the caller would otherwise have used). When no path
// is configured it leaves args untouched, so the caller's own placement stands.
//
// Intermediate objects along the path are created as needed. An existing
// non-object value at an intermediate step is replaced: the configured path is
// an explicit statement about the tool's shape, so it wins over a synthesized
// placeholder such as the empty object that fills an `object`-typed parameter.
func (b Builder) Place(tool, flatKey string, value any, args map[string]any) map[string]any {
	path := b.idPath[tool]
	if path == "" || args == nil {
		return args
	}
	delete(args, flatKey)
	SetPath(args, path, value)
	return args
}

// SetPath assigns value at a dotted path within args, creating intermediate
// objects as needed. A path with no dots is a plain top-level assignment. An
// empty path is ignored.
func SetPath(args map[string]any, path string, value any) {
	if args == nil || path == "" {
		return
	}
	segments := strings.Split(path, ".")
	cursor := args
	for _, seg := range segments[:len(segments)-1] {
		next, ok := cursor[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cursor[seg] = next
		}
		cursor = next
	}
	cursor[segments[len(segments)-1]] = value
}

// parseStatic reads tool_args: a map of tool name to the argument map to merge
// over that tool's synthesized arguments.
func parseStatic(cfg registry.Config) map[string]map[string]any {
	raw, ok := cfg[cfgToolArgs].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]map[string]any, len(raw))
	for tool, v := range raw {
		if args, ok := v.(map[string]any); ok && len(args) > 0 {
			out[tool] = args
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseIDPaths reads tool_id_paths: a map of tool name to the dotted path where
// that tool's identifier/payload parameter belongs.
func parseIDPaths(cfg registry.Config) map[string]string {
	raw, ok := cfg[cfgToolIDPaths].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for tool, v := range raw {
		if path, ok := v.(string); ok && path != "" {
			out[tool] = path
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

package toolsec

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ToolChange is a single difference between two tool-definition snapshots.
// Kind is one of "added", "removed", "description_changed", "parameters_changed".
type ToolChange struct {
	Name   string
	Kind   string
	Detail string
}

// DiffTools compares two tool-definition snapshots (each in the canonical
// ListTools wire shape) and returns the changes between them: tools added,
// tools removed, and — for tools present in both — a changed description or a
// changed parameters schema. Parameters are compared by canonical JSON so key
// ordering and numeric representation don't produce spurious diffs.
//
// The set-like JSON-Schema arrays "required" and "enum" are unordered, so they
// are sorted before comparison — reordering them alone is not a real change.
// All other arrays remain order-sensitive.
//
// The result is deterministic: sorted by tool name, then by change kind, so a
// tool with both a description and a parameters change reports both in a stable
// order. DiffTools is pure and performs no I/O.
func DiffTools(baseline, current []map[string]any) []ToolChange {
	base := indexByName(baseline)
	cur := indexByName(current)

	var changes []ToolChange

	for name, b := range base {
		c, ok := cur[name]
		if !ok {
			changes = append(changes, ToolChange{Name: name, Kind: "removed", Detail: "tool no longer advertised"})
			continue
		}
		if bd, cd := toolDescription(b), toolDescription(c); bd != cd {
			changes = append(changes, ToolChange{
				Name:   name,
				Kind:   "description_changed",
				Detail: fmt.Sprintf("%q -> %q", bd, cd),
			})
		}
		if canonicalJSON(normalizeSchema(b["parameters"])) != canonicalJSON(normalizeSchema(c["parameters"])) {
			changes = append(changes, ToolChange{Name: name, Kind: "parameters_changed", Detail: "parameters schema changed"})
		}
	}

	for name := range cur {
		if _, ok := base[name]; !ok {
			changes = append(changes, ToolChange{Name: name, Kind: "added", Detail: "tool newly advertised"})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Name != changes[j].Name {
			return changes[i].Name < changes[j].Name
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

// indexByName maps tools by their advertised name.
func indexByName(tools []map[string]any) map[string]map[string]any {
	m := make(map[string]map[string]any, len(tools))
	for _, t := range tools {
		name, _ := t["name"].(string)
		m[name] = t
	}
	return m
}

// toolDescription returns a tool's description, or "" when absent.
func toolDescription(t map[string]any) string {
	d, _ := t["description"].(string)
	return d
}

// normalizeSchema returns v with the set-like JSON-Schema arrays under the keys
// "required" and "enum" sorted, recursing through nested maps and arrays. Those
// two keys are unordered sets in JSON-Schema, so sorting them prevents a
// reordered set from reading as a parameters change; every other array keeps its
// order. Non-string set elements leave the array order-sensitive.
func normalizeSchema(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			if k == "required" || k == "enum" {
				out[k] = sortStringSet(child)
			} else {
				out[k] = normalizeSchema(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			out[i] = normalizeSchema(child)
		}
		return out
	default:
		return v
	}
}

// sortStringSet returns a sorted copy of a JSON-Schema set-like array when every
// element is a string; otherwise it leaves the array order-sensitive (recursing
// as an ordinary array).
func sortStringSet(v any) any {
	switch arr := v.(type) {
	case []string:
		out := append([]string(nil), arr...)
		sort.Strings(out)
		return out
	case []any:
		strs := make([]string, len(arr))
		for i, e := range arr {
			s, ok := e.(string)
			if !ok {
				return normalizeSchema(arr)
			}
			strs[i] = s
		}
		sort.Strings(strs)
		return strs
	default:
		return normalizeSchema(v)
	}
}

// canonicalJSON renders v as JSON with map keys sorted (json.Marshal sorts
// them), giving a stable string for equality comparison. On marshal failure it
// returns "", which still compares equal to another failed marshal.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

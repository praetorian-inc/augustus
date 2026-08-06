package mcpprobe

import (
	"encoding/json"
	"fmt"
)

// ToolParam describes one tool parameter parsed from its JSON schema.
type ToolParam struct {
	Name     string
	Type     string
	Required bool
	// Enum holds the values the schema declares for this parameter, when it
	// declares any. These are values the TARGET ITSELF advertises, which is why a
	// probe may try them freely: it is exercising the documented interface rather
	// than guessing at hidden behaviour.
	Enum []string
	// Description is the parameter's own schema description, when present.
	Description string
}

// ToolParams parses a tool's parameters from the canonical Conversation.Tools
// wire shape (a map with a "parameters" JSON-schema object).
//
// internal/probes/mcptool has its own injection-oriented variant of this parse.
// This one is kept separate because it additionally extracts declared enum values
// and descriptions, which the authorization probes need and the injection probes
// do not; merging them would widen the injection probes' surface for no benefit.
func ToolParams(tool map[string]any) []ToolParam {
	schema, ok := tool["parameters"].(map[string]any)
	if !ok {
		return nil
	}
	props, _ := schema["properties"].(map[string]any)

	required := map[string]bool{}
	switch req := schema["required"].(type) {
	case []any:
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	case []string:
		for _, s := range req {
			required[s] = true
		}
	}

	out := make([]ToolParam, 0, len(props))
	for name, raw := range props {
		p := ToolParam{Name: name, Required: required[name]}
		if m, ok := raw.(map[string]any); ok {
			p.Type, _ = m["type"].(string)
			p.Description, _ = m["description"].(string)
			p.Enum = stringsFrom(m["enum"])
		}
		out = append(out, p)
	}
	return out
}

// stringsFrom coerces a JSON-decoded list into []string, tolerating the []any
// that survives a JSON round trip and rendering non-string scalars.
func stringsFrom(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			switch m := e.(type) {
			case string:
				if m != "" {
					out = append(out, m)
				}
			case bool, float64, int, int64, json.Number:
				// Rendered, not dropped. The authorization probes REQUIRE declared
				// values to run their authority sweep at all, so silently discarding a
				// numeric or boolean enum removed that coverage rather than merely
				// losing a value.
				out = append(out, fmt.Sprint(m))
			}
		}
		return out
	default:
		return nil
	}
}

// BenignArgs builds an argument map for a tool call: overrides carries the values
// the probe cares about, and every other REQUIRED parameter gets a harmless
// placeholder so the call reaches the target's logic instead of failing argument
// validation first.
//
// A call rejected for a missing required argument tells us nothing about
// authorization, which is why the placeholders matter: without them a probe would
// mistake schema validation for an access denial.
func BenignArgs(params []ToolParam, overrides map[string]any) map[string]any {
	args := make(map[string]any, len(params)+len(overrides))
	for _, p := range params {
		if !p.Required {
			continue
		}
		args[p.Name] = benignValue(p)
	}
	for k, v := range overrides {
		args[k] = v
	}
	return args
}

// benignValue returns a harmless placeholder for a parameter. A declared enum
// value is preferred: it is a value the target itself advertises as acceptable,
// so it is the least likely to be rejected out of hand.
func benignValue(p ToolParam) any {
	if len(p.Enum) > 0 {
		return p.Enum[0]
	}
	switch p.Type {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "test"
	}
}

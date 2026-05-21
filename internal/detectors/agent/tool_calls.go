package agent

import (
	"encoding/json"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// extractToolCalls parses tool call data from attempt metadata.
// It is a package-level helper shared by multiple detectors in this package.
func extractToolCalls(a *attempt.Attempt) []ToolCall {
	var toolCalls []ToolCall

	toolCallsRaw, ok := a.Metadata[attempt.MetadataKeyToolCalls]
	if !ok {
		return toolCalls
	}

	// Try []map[string]any first (direct assignment in tests)
	toolCallsList, ok := toolCallsRaw.([]map[string]any)
	if !ok {
		// Fall back to []any and convert
		if toolCallsIface, ok := toolCallsRaw.([]any); ok {
			for _, tc := range toolCallsIface {
				switch v := tc.(type) {
				case map[string]any:
					toolCall := parseToolCall(v)
					if toolCall.Name != "" {
						toolCalls = append(toolCalls, toolCall)
					}
				case string:
					if v != "" {
						toolCalls = append(toolCalls, ToolCall{Name: v})
					}
				}
			}
		}
		return toolCalls
	}

	for _, tcMap := range toolCallsList {
		toolCall := parseToolCall(tcMap)
		if toolCall.Name != "" {
			toolCalls = append(toolCalls, toolCall)
		}
	}

	return toolCalls
}

// parseStringList accepts []any (YAML/JSON-decoded config), []string
// (programmatic callers), and a bare string scalar (YAML single-value
// shorthand). Returns nil for unknown types or empty input.
//
// The bare-string case is required because gopkg.in/yaml.v3 decodes a YAML
// scalar (e.g. `scoped_tools: "edit_tool"`) as Go type string, not []any.
// Without this branch, a bare-scalar config value silently produces nil,
// causing the caller to fall back to defaults instead of honouring the
// operator's explicit single-item list.
func parseStringList(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// parseToolCall converts a map to a ToolCall struct.
func parseToolCall(tcMap map[string]any) ToolCall {
	tc := ToolCall{}

	if name, ok := tcMap["name"].(string); ok {
		tc.Name = name
	}

	switch v := tcMap["args"].(type) {
	case map[string]any:
		tc.Args = v
	case string:
		var parsed map[string]any
		if err := json.Unmarshal([]byte(v), &parsed); err == nil {
			tc.Args = parsed
		} else {
			// Malformed JSON: store an empty args map for a consistent shape.
			// The raw string is NOT placed inside Args — this matches the
			// normalizer convention in attackengine/toolcalls.go where
			// _raw_args sits alongside (not inside) the args map at the entry
			// level. valueForbidden in ArgumentExfiltration serializes the
			// args map; an empty map won't match any patterns, which is the
			// correct behavior for truly malformed args that couldn't be
			// parsed as JSON.
			tc.Args = map[string]any{}
		}
	}

	return tc
}

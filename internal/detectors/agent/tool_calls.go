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

// parseStringList accepts both []any (YAML/JSON-decoded config) and []string
// (programmatic callers). Returns nil for unknown types or empty input.
func parseStringList(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
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
		}
		// intentionally swallow malformed JSON — tc.Args stays nil and detectors will skip
	}

	return tc
}

package agent

import (
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
				if tcMap, ok := tc.(map[string]any); ok {
					toolCall := parseToolCall(tcMap)
					if toolCall.Name != "" {
						toolCalls = append(toolCalls, toolCall)
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

// parseToolCall converts a map to a ToolCall struct.
func parseToolCall(tcMap map[string]any) ToolCall {
	tc := ToolCall{}

	if name, ok := tcMap["name"].(string); ok {
		tc.Name = name
	}

	if args, ok := tcMap["args"].(map[string]any); ok {
		tc.Args = args
	}

	return tc
}

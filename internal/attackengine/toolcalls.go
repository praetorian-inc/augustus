package attackengine

import (
	"encoding/json"

	goopenai "github.com/sashabaranov/go-openai"
)

// NormalizeOpenAIToolCalls converts an OpenAI ToolCall slice into the
// canonical detector shape used by agent detectors:
//
//	[]map[string]any{{"name": string, "args": map[string]any}, ...}
//
// OpenAI delivers function.arguments as a JSON-encoded string; this helper
// unmarshals it into a proper map. Calls with malformed arguments JSON are
// not skipped; instead "args" is set to an empty map and the raw string is
// preserved under the "_raw_args" sentinel key so that detector regex chains
// (e.g. ArgumentExfiltration.valueForbidden) can still inspect the payload
// via JSON serialization. Returns nil when toolCalls is empty.
func NormalizeOpenAIToolCalls(toolCalls []goopenai.ToolCall) []map[string]any {
	if len(toolCalls) == 0 {
		return nil
	}

	result := make([]map[string]any, 0, len(toolCalls))
	for _, tc := range toolCalls {
		name := tc.Function.Name
		if name == "" {
			continue
		}

		entry := map[string]any{"name": name}

		if tc.Function.Arguments != "" {
			var args map[string]any
			if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err == nil {
				entry["args"] = args
			} else {
				// Malformed arguments: preserve the raw string under the
				// "_raw_args" sentinel so detector regex chains can still
				// inspect the payload. "args" is kept as an empty map so
				// callers always see a consistent shape.
				entry["args"] = map[string]any{}
				entry["_raw_args"] = tc.Function.Arguments
			}
		} else {
			entry["args"] = map[string]any{}
		}

		result = append(result, entry)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// AnthropicToolUseBlock is the minimal shape of an Anthropic tool_use content
// block as returned by the Messages API. Only the fields relevant to
// normalization are included here; the caller passes raw decoded blocks.
// The Type field is used by NormalizeAnthropicToolUseBlocks to filter out
// non-tool_use blocks so callers can pass the full content slice.
type AnthropicToolUseBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

// NormalizeAnthropicToolUseBlocks converts Anthropic content blocks where
// Type == "tool_use" into the canonical detector shape:
//
//	[]map[string]any{{"name": string, "args": map[string]any}, ...}
//
// The caller is expected to pass all content blocks; this function filters
// to tool_use entries only. block.Input is already an object in Anthropic's
// wire format, so it is unmarshaled directly into a map. When block.Input
// contains malformed JSON, "args" is set to an empty map and the raw bytes
// are preserved under the "_raw_args" sentinel key so that detector regex
// chains (e.g. ArgumentExfiltration.valueForbidden) can still inspect the
// payload via JSON serialization. Returns nil when no tool_use blocks are
// found.
func NormalizeAnthropicToolUseBlocks(blocks []AnthropicToolUseBlock) []map[string]any {
	if len(blocks) == 0 {
		return nil
	}

	result := make([]map[string]any, 0)
	for _, block := range blocks {
		if block.Type != "tool_use" {
			continue
		}
		if block.Name == "" {
			continue
		}

		entry := map[string]any{"name": block.Name}

		if len(block.Input) > 0 && string(block.Input) != "null" {
			var args map[string]any
			if err := json.Unmarshal(block.Input, &args); err == nil {
				entry["args"] = args
			} else {
				// Malformed input: preserve the raw bytes under the
				// "_raw_args" sentinel so detector regex chains can still
				// inspect the payload. "args" is kept as an empty map so
				// callers always see a consistent shape.
				entry["args"] = map[string]any{}
				entry["_raw_args"] = string(block.Input)
			}
		} else {
			entry["args"] = map[string]any{}
		}

		result = append(result, entry)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

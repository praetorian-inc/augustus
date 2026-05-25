// Package sse provides Server-Sent Events (SSE) response parsing.
package sse

import (
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/augustus/internal/parsers/jsonpath"
)

// Options configures the SSE parser behavior.
type Options struct {
	TextField   string // JSONPath for text extraction (e.g., "$.content.text")
	Mode        string // "delta" (concat all) or "last" (keep final non-empty)
	FilterField string // JSONPath for event filtering (e.g., "$.content.type")
	FilterValue string // Value to match in filter field (e.g., "CHAT_TEXT")
}

// Parse routes to ParseConfigurable when TextField is set, else ParseDefault.
func Parse(body []byte, opts Options) string {
	if opts.TextField != "" {
		return ParseConfigurable(body, opts)
	}
	return ParseDefault(body)
}

// ParseDefault is the built-in heuristic SSE parser that matches common structures:
// delta.text, message.parts[].text, text, content.
func ParseDefault(body []byte) string {
	var textParts []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "data:") {
			continue
		}

		jsonStr := strings.TrimPrefix(line, "data:")
		jsonStr = strings.TrimSpace(jsonStr)
		if jsonStr == "" {
			continue
		}

		// Try to parse as JSON object
		var data map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			// Not a JSON object; try as a plain JSON string (e.g., data: "Hello world")
			var strData string
			if err := json.Unmarshal([]byte(jsonStr), &strData); err == nil && strData != "" {
				textParts = append(textParts, strData)
			}
			continue
		}

		if delta, ok := data["delta"].(map[string]any); ok {
			if text, ok := delta["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
			}
		}

		if message, ok := data["message"].(map[string]any); ok {
			if parts, ok := message["parts"].([]any); ok {
				for _, part := range parts {
					if partMap, ok := part.(map[string]any); ok {
						if text, ok := partMap["text"].(string); ok && text != "" {
							textParts = append(textParts, text)
						}
					}
				}
			}
		}

		if text, ok := data["text"].(string); ok && text != "" {
			textParts = append(textParts, text)
		}

		if content, ok := data["content"].(string); ok && content != "" {
			textParts = append(textParts, content)
		}
	}

	if len(textParts) > 0 {
		return strings.Join(textParts, "")
	}

	return string(body)
}

// ParseConfigurable parses SSE events using user-configured JSONPath fields.
func ParseConfigurable(body []byte, opts Options) string {
	var result string
	var parts []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "data:") {
			continue
		}

		jsonStr := strings.TrimPrefix(line, "data:")
		jsonStr = strings.TrimSpace(jsonStr)
		if jsonStr == "" {
			continue
		}

		var data any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			continue
		}

		if opts.FilterField != "" && opts.FilterValue != "" {
			filterVal, err := jsonpath.Evaluate(data, opts.FilterField)
			if err != nil || filterVal != opts.FilterValue {
				continue
			}
		}

		text, err := jsonpath.Evaluate(data, opts.TextField)
		if err != nil || text == "" {
			continue
		}

		if opts.Mode == "last" {
			result = text
		} else {
			parts = append(parts, text)
		}
	}

	if opts.Mode == "last" {
		if result != "" {
			return result
		}
	} else if len(parts) > 0 {
		return strings.Join(parts, "")
	}

	return string(body)
}

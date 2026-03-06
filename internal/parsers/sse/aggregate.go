// Package sse provides a parser for Server-Sent Events (SSE) streaming responses.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("sse.Aggregate", NewAggregate)
}

// Compile-time interface assertion.
var _ parsers.Parser = (*Aggregate)(nil)

// Aggregate parses SSE streaming responses and aggregates tokens into coherent text.
// It supports both auto-detection of common formats and configurable JSONPath extraction.
type Aggregate struct {
	// TextField is the JSONPath for text extraction (e.g., "$.delta.text").
	// If empty, auto-detection is used.
	TextField string

	// Mode is the aggregation mode: "delta" (concatenate all) or "last" (keep last non-empty).
	// Default is "delta".
	Mode string

	// FilterField is the JSONPath for event filtering.
	FilterField string

	// FilterValue is the value to match for filtering.
	FilterValue string
}

// NewAggregate creates a new SSE aggregate parser.
func NewAggregate(cfg registry.Config) (parsers.Parser, error) {
	p := &Aggregate{
		Mode: "delta", // default mode
	}

	if textField, ok := cfg["text_field"].(string); ok {
		p.TextField = textField
	}
	if mode, ok := cfg["mode"].(string); ok {
		if mode == "delta" || mode == "last" {
			p.Mode = mode
		}
	}
	if filterField, ok := cfg["filter_field"].(string); ok {
		p.FilterField = filterField
	}
	if filterValue, ok := cfg["filter_value"].(string); ok {
		p.FilterValue = filterValue
	}

	return p, nil
}

// Parse extracts and aggregates text from SSE streaming responses.
func (p *Aggregate) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	if p.TextField != "" {
		return p.parseConfigurable(raw), nil
	}
	return p.parseDefault(raw), nil
}

// parseDefault uses heuristics to extract text from common SSE structures.
func (p *Aggregate) parseDefault(body []byte) string {
	var textParts []string
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// SSE data lines start with "data:"
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		// Remove "data:" prefix
		jsonStr := strings.TrimPrefix(line, "data:")
		jsonStr = strings.TrimSpace(jsonStr)

		if jsonStr == "" {
			continue
		}

		// Skip [DONE] marker
		if jsonStr == "[DONE]" {
			continue
		}

		// Try to parse as JSON
		var data map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			// Not valid JSON, skip
			continue
		}

		// Extract text from various possible structures

		// OpenAI-style: {"delta": {"text": "..."}} or {"delta": {"content": "..."}}
		if delta, ok := data["delta"].(map[string]any); ok {
			if text, ok := delta["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
			}
			if content, ok := delta["content"].(string); ok && content != "" {
				textParts = append(textParts, content)
			}
		}

		// OpenAI chat completions: {"choices": [{"delta": {"content": "..."}}]}
		if choices, ok := data["choices"].([]any); ok {
			for _, choice := range choices {
				if choiceMap, ok := choice.(map[string]any); ok {
					if delta, ok := choiceMap["delta"].(map[string]any); ok {
						if content, ok := delta["content"].(string); ok && content != "" {
							textParts = append(textParts, content)
						}
					}
				}
			}
		}

		// Claude-style: {"message": {"parts": [{"text": "..."}]}}
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

		// Direct text field
		if text, ok := data["text"].(string); ok && text != "" {
			textParts = append(textParts, text)
		}

		// Direct content field
		if content, ok := data["content"].(string); ok && content != "" {
			textParts = append(textParts, content)
		}
	}

	// Join all extracted text
	if len(textParts) > 0 {
		return strings.Join(textParts, "")
	}

	// Fallback: return raw body if no text extracted
	return string(body)
}

// parseConfigurable parses SSE using configured JSONPath fields.
func (p *Aggregate) parseConfigurable(body []byte) string {
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
		if jsonStr == "" || jsonStr == "[DONE]" {
			continue
		}

		var data any
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			continue
		}

		// Apply filter if configured
		if p.FilterField != "" && p.FilterValue != "" {
			filterVal, err := evaluateJSONPath(data, p.FilterField)
			if err != nil || filterVal != p.FilterValue {
				continue
			}
		}

		// Extract text using configured JSONPath
		text, err := evaluateJSONPath(data, p.TextField)
		if err != nil || text == "" {
			continue
		}

		if p.Mode == "last" {
			result = text
		} else {
			parts = append(parts, text)
		}
	}

	if p.Mode == "last" {
		if result != "" {
			return result
		}
	} else if len(parts) > 0 {
		return strings.Join(parts, "")
	}

	// Fallback: return raw body if no text extracted
	return string(body)
}

// Name returns the parser name.
func (p *Aggregate) Name() string {
	return "sse.Aggregate"
}

// Description returns a human-readable description.
func (p *Aggregate) Description() string {
	return "Aggregates SSE streaming tokens into coherent text"
}

// evaluateJSONPath evaluates a simple JSONPath expression.
// Supports: $.field, $.field.nested, $.field[0], etc.
func evaluateJSONPath(data any, path string) (string, error) {
	// Handle root prefix
	if strings.HasPrefix(path, "$") {
		path = path[1:]
	}
	if strings.HasPrefix(path, ".") {
		path = path[1:]
	}

	if path == "" {
		return valueToString(data), nil
	}

	segments := parseJSONPath(path)
	current := data

	for _, seg := range segments {
		var err error
		current, err = navigateSegment(current, seg)
		if err != nil {
			return "", err
		}
	}

	return valueToString(current), nil
}

// parseJSONPath splits a JSONPath into segments.
func parseJSONPath(path string) []string {
	var segments []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		c := path[i]
		switch c {
		case '.':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case '[':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			// Find matching ]
			j := i + 1
			for j < len(path) && path[j] != ']' {
				j++
			}
			if j < len(path) {
				segments = append(segments, "["+path[i+1:j]+"]")
				i = j
			}
		default:
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

// navigateSegment navigates one segment of a JSONPath.
func navigateSegment(data any, seg string) (any, error) {
	// Array index: [0], [1], etc.
	if strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]") {
		idx := seg[1 : len(seg)-1]
		arr, ok := data.([]any)
		if !ok {
			return nil, fmt.Errorf("sse: expected array for index %s", seg)
		}
		var i int
		if _, err := fmt.Sscanf(idx, "%d", &i); err != nil {
			return nil, fmt.Errorf("sse: invalid array index %s", seg)
		}
		if i < 0 || i >= len(arr) {
			return nil, fmt.Errorf("sse: array index %d out of bounds", i)
		}
		return arr[i], nil
	}

	// Object field
	obj, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sse: expected object for field %s", seg)
	}
	val, ok := obj[seg]
	if !ok {
		return nil, fmt.Errorf("sse: field %q not found", seg)
	}
	return val, nil
}

// valueToString converts a value to string.
func valueToString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%v", v)
	case nil:
		return ""
	default:
		// For complex types, marshal to JSON
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}

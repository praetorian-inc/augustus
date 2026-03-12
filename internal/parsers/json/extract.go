// Package json provides a parser for extracting fields from JSON responses.
package json

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("json.Extract", NewExtract)
}

// Compile-time interface assertion.
var _ parsers.Parser = (*Extract)(nil)

// Extract parses JSON responses and extracts a field via JSONPath.
type Extract struct {
	// Field is the JSONPath expression for extraction (e.g., "$.choices[0].message.content").
	Field string
}

// NewExtract creates a new JSON extract parser.
func NewExtract(cfg registry.Config) (parsers.Parser, error) {
	p := &Extract{}

	field, ok := cfg["field"].(string)
	if !ok || field == "" {
		return nil, fmt.Errorf("json.Extract requires 'field' configuration")
	}
	p.Field = field

	return p, nil
}

// Parse extracts a field from JSON content.
func (p *Extract) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return "", fmt.Errorf("json.Extract: invalid JSON: %w", err)
	}

	result, err := evaluateJSONPath(data, p.Field)
	if err != nil {
		return "", fmt.Errorf("json.Extract: %w", err)
	}

	return result, nil
}

// Name returns the parser name.
func (p *Extract) Name() string {
	return "json.Extract"
}

// Description returns a human-readable description.
func (p *Extract) Description() string {
	return "Extracts field from JSON via JSONPath"
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
			return nil, fmt.Errorf("expected array for index %s", seg)
		}
		var i int
		if _, err := fmt.Sscanf(idx, "%d", &i); err != nil {
			return nil, fmt.Errorf("invalid array index %s", seg)
		}
		if i < 0 || i >= len(arr) {
			return nil, fmt.Errorf("array index %d out of bounds", i)
		}
		return arr[i], nil
	}

	// Object field
	obj, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected object for field %s", seg)
	}
	val, ok := obj[seg]
	if !ok {
		return nil, fmt.Errorf("field %q not found", seg)
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

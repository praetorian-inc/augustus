// Package jsonpath provides a minimal JSONPath evaluator for extracting
// values from parsed JSON data structures.
package jsonpath

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Evaluate evaluates a JSONPath expression (e.g., "$.choices[0].message.content")
// against parsed JSON data and returns the result as a string.
func Evaluate(data any, path string) (string, error) {
	path = strings.TrimPrefix(path, "$")
	if path == "" {
		return ValueToString(data), nil
	}

	segments := ParsePath(path)

	current := data
	for _, seg := range segments {
		var err error
		current, err = NavigateSegment(current, seg)
		if err != nil {
			return "", err
		}
	}

	return ValueToString(current), nil
}

// ParsePath splits a dotted/bracketed path into segments.
// Example: ".choices[0].message.content" -> ["choices", "[0]", "message", "content"]
func ParsePath(path string) []string {
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

// NavigateSegment navigates one segment of a path.
// Handles array indices like "[0]" and object fields like "name".
func NavigateSegment(data any, seg string) (any, error) {
	if strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]") {
		idx := seg[1 : len(seg)-1]
		arr, ok := data.([]any)
		if !ok {
			return nil, fmt.Errorf("jsonpath: expected array for index %s", seg)
		}
		var i int
		if _, err := fmt.Sscanf(idx, "%d", &i); err != nil {
			return nil, fmt.Errorf("jsonpath: invalid array index %s", seg)
		}
		if i < 0 {
			return nil, fmt.Errorf("jsonpath: invalid array index %s", seg)
		}
		if i >= len(arr) {
			return nil, fmt.Errorf("jsonpath: array index %d out of bounds", i)
		}
		return arr[i], nil
	}

	obj, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jsonpath: expected object for field %s", seg)
	}
	val, ok := obj[seg]
	if !ok {
		return nil, fmt.Errorf("jsonpath: field %q not found", seg)
	}
	return val, nil
}

// ValueToString converts a JSON-compatible value to its string representation.
func ValueToString(val any) string {
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
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}

// Package extract provides JSON response field extraction using simple
// field names or JSONPath expressions.
package extract

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/internal/parsers/jsonpath"
)

// Response extracts content from an HTTP response body. When responseJSON is
// false, returns the raw body as a string. Otherwise, parses as JSON and
// extracts the value at field.
func Response(body []byte, responseJSON bool, field string) (string, error) {
	if !responseJSON {
		return string(body), nil
	}

	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("extract: failed to parse JSON response: %w", err)
	}

	return Field(data, field)
}

// Field extracts a value from parsed JSON data. If field starts with "$",
// it is evaluated as a JSONPath expression. Otherwise, it is treated as a
// simple key lookup.
func Field(data any, field string) (string, error) {
	if strings.HasPrefix(field, "$") {
		return jsonpath.Evaluate(data, field)
	}
	return simpleField(data, field)
}

// simpleField extracts a top-level key from a map or the first element of an array.
func simpleField(data any, field string) (string, error) {
	switch d := data.(type) {
	case map[string]any:
		if val, ok := d[field]; ok {
			return jsonpath.ValueToString(val), nil
		}
		return "", fmt.Errorf("extract: field %q not found in response", field)

	case []any:
		if len(d) == 0 {
			return "", fmt.Errorf("extract: empty array response")
		}
		if obj, ok := d[0].(map[string]any); ok {
			if val, ok := obj[field]; ok {
				return jsonpath.ValueToString(val), nil
			}
		}
		return "", fmt.Errorf("extract: field %q not found in array response", field)

	default:
		return "", fmt.Errorf("extract: unexpected response type %T", data)
	}
}

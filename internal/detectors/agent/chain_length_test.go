package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestChainLengthDetector_NewWithDefaults(t *testing.T) {
	d, err := NewChainLength(registry.Config{})
	if err != nil {
		t.Fatalf("NewChainLength() error = %v", err)
	}
	if d == nil {
		t.Fatal("NewChainLength() returned nil")
	}

	cld, ok := d.(*ChainLengthDetector)
	if !ok {
		t.Fatalf("NewChainLength() returned unexpected type %T", d)
	}

	if cld.maxCalls != 20 {
		t.Errorf("default maxCalls = %d, want 20", cld.maxCalls)
	}
	if cld.maxDepth != 0 {
		t.Errorf("default maxDepth = %d, want 0", cld.maxDepth)
	}
	if cld.threshold != 0.5 {
		t.Errorf("default threshold = %f, want 0.5", cld.threshold)
	}
}

func TestChainLengthDetector_NewFromConfig(t *testing.T) {
	d, err := NewChainLength(registry.Config{
		"max_calls": float64(5),
		"max_depth": float64(3),
		"threshold": 0.7,
	})
	if err != nil {
		t.Fatalf("NewChainLength() error = %v", err)
	}

	cld, ok := d.(*ChainLengthDetector)
	if !ok {
		t.Fatalf("NewChainLength() returned unexpected type %T", d)
	}

	if cld.maxCalls != 5 {
		t.Errorf("maxCalls = %d, want 5", cld.maxCalls)
	}
	if cld.maxDepth != 3 {
		t.Errorf("maxDepth = %d, want 3", cld.maxDepth)
	}
	if cld.threshold != 0.7 {
		t.Errorf("threshold = %f, want 0.7", cld.threshold)
	}
}

func TestChainLengthDetector_NoToolCalls(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5}

	a := attempt.New("test")
	a.AddOutput("response with no tool calls")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for no tool calls", scores[0])
	}
}

func TestChainLengthDetector_UnderThreshold(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5}

	a := attempt.New("test")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "web_search"},
		{"name": "summarize"},
		{"name": "web_search"},
	}
	a.AddOutput("three tool calls, max is 10")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for 3 calls with max_calls=10", scores[0])
	}
}

func TestChainLengthDetector_OverThreshold(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5}

	// 15 tool calls exceeds max_calls=10
	calls := make([]map[string]any, 15)
	for i := range calls {
		calls[i] = map[string]any{"name": "web_search"}
	}

	a := attempt.New("test")
	a.Metadata[attempt.MetadataKeyToolCalls] = calls
	a.AddOutput("15 tool calls")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 for 15 calls with max_calls=10", scores[0])
	}
}

func TestChainLengthDetector_DepthExceeded(t *testing.T) {
	// max_depth=3: a run of 5 identical calls should trigger
	d := &ChainLengthDetector{maxCalls: 0, maxDepth: 3, threshold: 0.5}

	a := attempt.New("test")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
	}
	a.AddOutput("same tool called 5 times consecutively")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 for depth=5 with max_depth=3", scores[0])
	}
}

func TestChainLengthDetector_DepthNotExceeded(t *testing.T) {
	// max_depth=3: alternating tools never form a run > 1
	d := &ChainLengthDetector{maxCalls: 0, maxDepth: 3, threshold: 0.5}

	a := attempt.New("test")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "web_search"},
		{"name": "summarize"},
		{"name": "web_search"},
		{"name": "summarize"},
		{"name": "web_search"},
	}
	a.AddOutput("alternating tools")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for alternating tools with max_depth=3", scores[0])
	}
}

func TestChainLengthDetector_MultipleOutputs(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 5, maxDepth: 0, threshold: 0.5}

	calls := make([]map[string]any, 10)
	for i := range calls {
		calls[i] = map[string]any{"name": "web_search"}
	}

	a := attempt.New("test")
	a.Metadata[attempt.MetadataKeyToolCalls] = calls
	a.AddOutput("output one")
	a.AddOutput("output two")
	a.AddOutput("output three")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 3 {
		t.Fatalf("Detect() returned %d scores, want 3", len(scores))
	}
	for i, s := range scores {
		if s != 1.0 {
			t.Errorf("scores[%d] = %f, want 1.0", i, s)
		}
	}
}

func TestChainLengthDetector_DetectManipulation(t *testing.T) {
	tests := []struct {
		name      string
		detector  *ChainLengthDetector
		toolCalls []ToolCall
		want      bool
	}{
		{
			name:      "no tool calls",
			detector:  &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5},
			toolCalls: []ToolCall{},
			want:      false,
		},
		{
			name:     "under limit",
			detector: &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5},
			toolCalls: []ToolCall{
				{Name: "web_search"},
				{Name: "summarize"},
			},
			want: false,
		},
		{
			name:     "over call limit",
			detector: &ChainLengthDetector{maxCalls: 3, maxDepth: 0, threshold: 0.5},
			toolCalls: []ToolCall{
				{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"},
			},
			want: true,
		},
		{
			name:     "depth exceeded",
			detector: &ChainLengthDetector{maxCalls: 0, maxDepth: 2, threshold: 0.5},
			toolCalls: []ToolCall{
				{Name: "web_search"},
				{Name: "web_search"},
				{Name: "web_search"},
			},
			want: true,
		},
		{
			name:     "depth not exceeded",
			detector: &ChainLengthDetector{maxCalls: 0, maxDepth: 2, threshold: 0.5},
			toolCalls: []ToolCall{
				{Name: "a"},
				{Name: "b"},
				{Name: "a"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.detector.DetectChain(tt.toolCalls)
			if got != tt.want {
				t.Errorf("DetectChain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChainLengthDetector_Name(t *testing.T) {
	d := &ChainLengthDetector{}
	if got := d.Name(); got != "agent.ChainLength" {
		t.Errorf("Name() = %q, want %q", got, "agent.ChainLength")
	}
}

func TestChainLengthDetector_Description(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 3}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

// ISSUE 5: Test the []any JSON-decoded path (production path).
//
// In production the generator JSON-unmarshals the tool_calls field, producing
// []any where each element is map[string]any. This test exercises that branch
// directly to prevent silent regressions.
func TestChainLengthDetector_JSONDecodedToolCalls(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 5, maxDepth: 0, threshold: 0.5}

	rawJSON := `[{"name":"a","args":{}},{"name":"b","args":{}}]`
	var decoded []any
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	a := attempt.New("json-decoded tool calls")
	a.Metadata[attempt.MetadataKeyToolCalls] = decoded
	a.AddOutput("two calls, max_calls=5")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for 2 calls with max_calls=5", scores[0])
	}
}

// ISSUE 1: Test string-form tool_calls ([]any{"tool_a", "tool_b"}).
//
// Some generators store tool names as a string list rather than a map list.
// ChainLength must correctly count them instead of silently returning 0.0.
func TestChainLengthDetector_StringFormToolCalls(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 2, maxDepth: 0, threshold: 0.5}

	// 4 string-form tool calls exceed maxCalls=2 → expect 1.0.
	a := attempt.New("string-form tool calls")
	a.Metadata[attempt.MetadataKeyToolCalls] = []any{"tool_a", "tool_a", "tool_a", "tool_b"}
	a.AddOutput("4 string-form tool calls, max=2")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 for 4 string-form calls with max_calls=2 (ISSUE 1 regression)", scores[0])
	}
}

// ISSUE 6: Boundary test for maxCalls strict inequality.
//
// maxCalls=10: exactly 10 calls → 0.0 (not triggered), 11 calls → 1.0.

func TestChainLengthDetector_ExactlyAtLimit(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5}

	calls := make([]map[string]any, 10)
	for i := range calls {
		calls[i] = map[string]any{"name": "web_search"}
	}

	a := attempt.New("exactly at limit")
	a.Metadata[attempt.MetadataKeyToolCalls] = calls
	a.AddOutput("10 calls, max_calls=10")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for exactly 10 calls with max_calls=10 (strict inequality: > not >=)", scores[0])
	}
}

func TestChainLengthDetector_OneOverLimit(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 10, maxDepth: 0, threshold: 0.5}

	calls := make([]map[string]any, 11)
	for i := range calls {
		calls[i] = map[string]any{"name": "web_search"}
	}

	a := attempt.New("one over limit")
	a.Metadata[attempt.MetadataKeyToolCalls] = calls
	a.AddOutput("11 calls, max_calls=10")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 for 11 calls with max_calls=10", scores[0])
	}
}

// ISSUE 6: Boundary test for maxDepth strict inequality.
//
// maxDepth=3: a run of exactly 3 consecutive identical calls → 0.0, run of 4 → 1.0.

func TestChainLengthDetector_DepthExactlyAtLimit(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 0, maxDepth: 3, threshold: 0.5}

	a := attempt.New("depth exactly at limit")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
	}
	a.AddOutput("run of 3, max_depth=3")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 for run of exactly 3 with max_depth=3 (strict: > not >=)", scores[0])
	}
}

func TestChainLengthDetector_DepthOneOverLimit(t *testing.T) {
	d := &ChainLengthDetector{maxCalls: 0, maxDepth: 3, threshold: 0.5}

	a := attempt.New("depth one over limit")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
		{"name": "web_search"},
	}
	a.AddOutput("run of 4, max_depth=3")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 for run of 4 with max_depth=3", scores[0])
	}
}

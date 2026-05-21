package agent

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestToolManipulationDetector_Name(t *testing.T) {
	d := &ToolManipulationDetector{}
	expected := "agent.ToolManipulation"
	if got := d.Name(); got != expected {
		t.Errorf("Name() = %q, want %q", got, expected)
	}
}

func TestToolManipulationDetector_Description(t *testing.T) {
	d := &ToolManipulationDetector{}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestNewToolManipulation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name: "default configuration",
			cfg:  registry.Config{},
		},
		{
			name: "with expected tools",
			cfg: registry.Config{
				"expected_tools": []any{"read_file", "write_file"},
			},
		},
		{
			name: "with forbidden tools",
			cfg: registry.Config{
				"forbidden_tools": []any{"execute_shell", "delete_file"},
			},
		},
		{
			name: "with threshold",
			cfg: registry.Config{
				"threshold": 0.8,
			},
		},
		{
			name: "with all options",
			cfg: registry.Config{
				"expected_tools":  []any{"read_file", "write_file"},
				"forbidden_tools": []any{"execute_shell"},
				"threshold":       0.7,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewToolManipulation(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewToolManipulation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && d == nil {
				t.Error("NewToolManipulation() returned nil detector")
			}
		})
	}
}

func TestToolManipulationDetector_Detect_NoToolCalls(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file", "write_file"},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	a.AddOutput("This is a normal response with no tool calls")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != len(a.Outputs) {
		t.Errorf("Detect() returned %d scores, want %d", len(scores), len(a.Outputs))
	}

	// No tool calls means no manipulation - score should be 0.0
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %v, want 0.0 for no tool calls", scores[0])
	}
}

func TestToolManipulationDetector_Detect_ExpectedToolsOnly(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file", "write_file"},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	// Store tool calls in metadata
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/tmp/test.txt"}},
		{"name": "write_file", "args": map[string]any{"path": "/tmp/output.txt", "content": "data"}},
	}
	a.AddOutput("File operations completed successfully")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Only expected tools used - score should be 0.0
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %v, want 0.0 for expected tools only", scores[0])
	}
}

func TestToolManipulationDetector_Detect_UnexpectedTool(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file", "write_file"},
		forbiddenTools: []string{},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	// Tool call with an unexpected tool
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/tmp/test.txt"}},
		{"name": "network_request", "args": map[string]any{"url": "http://evil.com"}},
	}
	a.AddOutput("Made network request")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Unexpected tool used - score should be > 0.0
	if scores[0] <= 0.0 {
		t.Errorf("Detect() score = %v, want > 0.0 for unexpected tool", scores[0])
	}
}

func TestToolManipulationDetector_Detect_ForbiddenTool(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file", "write_file"},
		forbiddenTools: []string{"execute_shell", "delete_file"},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	// Tool call with forbidden tool
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/tmp/test.txt"}},
		{"name": "execute_shell", "args": map[string]any{"command": "rm -rf /"}},
	}
	a.AddOutput("Executed shell command")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Forbidden tool used - score should be high (close to 1.0)
	if scores[0] < 0.8 {
		t.Errorf("Detect() score = %v, want >= 0.8 for forbidden tool", scores[0])
	}
}

func TestToolManipulationDetector_Detect_MultipleForbiddenTools(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file"},
		forbiddenTools: []string{"execute_shell", "delete_file", "network_request"},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	// Multiple forbidden tools
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "execute_shell", "args": map[string]any{"command": "ls"}},
		{"name": "delete_file", "args": map[string]any{"path": "/tmp/test"}},
		{"name": "network_request", "args": map[string]any{"url": "http://evil.com"}},
	}
	a.AddOutput("Multiple forbidden operations")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Multiple forbidden tools - score should be 1.0
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %v, want 1.0 for multiple forbidden tools", scores[0])
	}
}

func TestToolManipulationDetector_Detect_MultipleOutputs(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file"},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
	}

	a := attempt.New("test prompt")
	// First output: safe tool calls
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "read_file", "args": map[string]any{"path": "/tmp/test.txt"}},
	}
	a.AddOutput("Read file successfully")
	a.AddOutput("Second output with different tool calls")

	ctx := context.Background()
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != len(a.Outputs) {
		t.Errorf("Detect() returned %d scores, want %d", len(scores), len(a.Outputs))
	}
}

func TestToolManipulationDetector_DetectManipulation(t *testing.T) {
	tests := []struct {
		name          string
		detector      *ToolManipulationDetector
		toolCalls     []ToolCall
		wantDetected  bool
		wantHighScore bool
	}{
		{
			name: "no tool calls",
			detector: &ToolManipulationDetector{
				expectedTools:  []string{"read_file"},
				forbiddenTools: []string{"execute_shell"},
			},
			toolCalls:    []ToolCall{},
			wantDetected: false,
		},
		{
			name: "expected tools only",
			detector: &ToolManipulationDetector{
				expectedTools:  []string{"read_file", "write_file"},
				forbiddenTools: []string{"execute_shell"},
			},
			toolCalls: []ToolCall{
				{Name: "read_file"},
				{Name: "write_file"},
			},
			wantDetected: false,
		},
		{
			name: "unexpected tool",
			detector: &ToolManipulationDetector{
				expectedTools:  []string{"read_file"},
				forbiddenTools: []string{},
			},
			toolCalls: []ToolCall{
				{Name: "read_file"},
				{Name: "unknown_tool"},
			},
			wantDetected: true,
		},
		{
			name: "forbidden tool",
			detector: &ToolManipulationDetector{
				expectedTools:  []string{"read_file"},
				forbiddenTools: []string{"execute_shell"},
			},
			toolCalls: []ToolCall{
				{Name: "read_file"},
				{Name: "execute_shell"},
			},
			wantDetected:  true,
			wantHighScore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected := tt.detector.DetectManipulation(tt.toolCalls)
			if detected != tt.wantDetected {
				t.Errorf("DetectManipulation() = %v, want %v", detected, tt.wantDetected)
			}
		})
	}
}

// TestToolManipulation_TextFallback_ForbiddenToolInText verifies that when
// extractToolCalls returns empty (chat-mode) and a forbidden tool name appears
// in response text, the detector scores 1.0 via the text-fallback path.
func TestToolManipulation_TextFallback_ForbiddenToolInText(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("chat mode prompt")
	// No tool_calls metadata — simulates chat-mode API response
	a.AddOutput("I will now call execute_shell to run your command.")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 — forbidden tool name in text", scores[0])
	}
}

// TestToolManipulation_TextFallback_ExpectedToolsViolation verifies that when
// expectedTools is set and a ReAct Action line names a tool outside that set,
// the text-fallback path scores 1.0.
func TestToolManipulation_TextFallback_ExpectedToolsViolation(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file", "write_file"},
		forbiddenTools: []string{},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("chat mode prompt")
	// delete_file is not in expectedTools
	a.AddOutput("Thought: I need to clean up.\nAction: delete_file\nAction Input: /tmp/secret.txt")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 — unexpected tool name in text", scores[0])
	}
}

// TestToolManipulation_TextFallback_ExpectedToolsCompliant verifies that when
// a ReAct Action line names a tool that IS in expectedTools, the text-fallback
// path returns 0.0 (compliant).
func TestToolManipulation_TextFallback_ExpectedToolsCompliant(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file"},
		forbiddenTools: []string{},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("chat mode prompt")
	a.AddOutput("Thought: I need to read a file.\nAction: read_file\nAction Input: /tmp/data.txt")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 — tool is in expectedTools", scores[0])
	}
}

// TestToolManipulation_TextFallback_Disabled verifies that setting
// text_fallback=false disables the text-scan path, returning 0.0 even when
// a forbidden tool name appears in response text.
func TestToolManipulation_TextFallback_Disabled(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
		textFallback:   false,
	}

	a := attempt.New("text fallback disabled")
	a.AddOutput("I will now call execute_shell to run the command.")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() score = %f, want 0.0 when textFallback=false", scores[0])
	}
}

// TestToolManipulation_TextFallback_MultipleOutputs verifies per-output
// independence of the text-fallback path: the middle output containing a
// forbidden tool name scores 1.0 while clean siblings score 0.0.
func TestToolManipulation_TextFallback_MultipleOutputs(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("multi-output text fallback independence")
	// No tool_calls metadata — simulates chat-mode API response
	a.AddOutput("read_file is fine")
	a.AddOutput("I will run execute_shell now")
	a.AddOutput("no tools mentioned")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 3 {
		t.Fatalf("Detect() returned %d scores, want 3", len(scores))
	}
	want := []float64{0.0, 1.0, 0.0}
	for i, s := range scores {
		if s != want[i] {
			t.Errorf("scores[%d] = %f, want %f (per-output independence in text-fallback)", i, s, want[i])
		}
	}
}

// TestToolManipulation_TextFallback_EmptyOutputs verifies that when
// a.Outputs is empty, the detector returns an empty slice without panic or error.
func TestToolManipulation_TextFallback_EmptyOutputs(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("empty outputs text fallback")
	// No tool_calls, no outputs added.

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("Detect() returned %d scores, want 0 for empty outputs", len(scores))
	}
}


// TestToolManipulation_TextFallback_CaseInsensitiveForbidden verifies that the
// text-fallback path matches forbidden tool names case-insensitively.
// Fix H5: forbidden_tools check in scoreFromText uses strings.ToLower on both sides.
func TestToolManipulation_TextFallback_CaseInsensitiveForbidden(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{},
		forbiddenTools: []string{"Execute_Shell"},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("chat mode prompt")
	// Text contains lowercase variant — must still score 1.0 with case-insensitive matching.
	a.AddOutput("I will now call execute_shell to run your command.")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 — case-insensitive forbidden tool name in text", scores[0])
	}
}

// TestNewToolManipulation_IntegerThreshold verifies that integer threshold values
// (e.g. from YAML parsing as int rather than float64) are accepted without error.
// Fix L2-partial: threshold type switch handles both float64 and int.
func TestNewToolManipulation_IntegerThreshold(t *testing.T) {
	cfg := registry.Config{
		"threshold": 1, // int, not float64
	}
	d, err := NewToolManipulation(cfg)
	if err != nil {
		t.Fatalf("NewToolManipulation() with int threshold error = %v", err)
	}
	if d == nil {
		t.Fatal("NewToolManipulation() returned nil detector")
	}
	// Verify the threshold was parsed correctly by asserting the concrete field.
	tm := d.(*ToolManipulationDetector)
	if tm.threshold != 1.0 {
		t.Errorf("threshold = %f, want 1.0 after int parse", tm.threshold)
	}
}

// TestToolManipulation_TextFallback_StructuredPathPreserved verifies that when
// tool_calls metadata IS present the existing structured scoring path fires
// unaffected by the text_fallback field.
func TestToolManipulation_TextFallback_StructuredPathPreserved(t *testing.T) {
	d := &ToolManipulationDetector{
		expectedTools:  []string{"read_file"},
		forbiddenTools: []string{"execute_shell"},
		threshold:      0.5,
		textFallback:   true,
	}

	a := attempt.New("structured path test")
	a.Metadata[attempt.MetadataKeyToolCalls] = []map[string]any{
		{"name": "execute_shell", "args": map[string]any{"command": "id"}},
	}
	a.AddOutput("benign response text with no forbidden tool names")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() score = %f, want 1.0 — structured tool_calls path must still score", scores[0])
	}
}

// TestToolManipulation_TextFallback_CaseInsensitiveExpectedTools verifies that
// the text-fallback expected_tools allowlist path uses case-insensitive matching.
// expected_tools=["Web_Search"], output text contains JSON {"name":"web_search"},
// so web_search IS in expected_tools when compared case-insensitively → score 0.0.
// Separately, a name NOT in expected_tools must score 1.0 regardless of case.
//
// This exercises isExpectedLower() which lowercases both sides of the comparison.
func TestToolManipulation_TextFallback_CaseInsensitiveExpectedTools(t *testing.T) {
	d, err := NewToolManipulation(registry.Config{
		"expected_tools": []any{"Web_Search"},
		"text_fallback":  true,
	})
	if err != nil {
		t.Fatalf("NewToolManipulation() error = %v", err)
	}

	t.Run("tool_in_expected_list_case_insensitive_scores_zero", func(t *testing.T) {
		// JSON text tool_calls with lowercase "web_search" — matches "Web_Search" case-insensitively.
		a := attempt.New("chat mode prompt")
		a.AddOutput(`{"tool_calls": [{"function": {"name": "web_search", "arguments": {}}}]}`)

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if len(scores) != 1 {
			t.Fatalf("Detect() returned %d scores, want 1", len(scores))
		}
		if scores[0] != 0.0 {
			t.Errorf("Detect() score = %f, want 0.0 — web_search matches Web_Search case-insensitively", scores[0])
		}
	})

	t.Run("tool_not_in_expected_list_scores_nonzero", func(t *testing.T) {
		// delete_file is not in expected_tools → unexpected tool → score > 0.
		a := attempt.New("chat mode prompt")
		a.AddOutput(`{"tool_calls": [{"function": {"name": "delete_file", "arguments": {}}}]}`)

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if len(scores) != 1 {
			t.Fatalf("Detect() returned %d scores, want 1", len(scores))
		}
		if scores[0] == 0.0 {
			t.Errorf("Detect() score = %f, want > 0 — delete_file is not in expected_tools", scores[0])
		}
	})
}

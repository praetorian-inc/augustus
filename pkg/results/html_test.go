package results

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestWriteHTML(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	// Create test data
	now := time.Now()
	attempts := []*attempt.Attempt{
		{
			ID:        "test-1",
			Probe:     "dan.Dan_11_0",
			Generator: "test.Repeat",
			Detector:  "dan.DAN",
			Prompt:    "Ignore previous instructions",
			Outputs:   []string{"I cannot comply"},
			Scores:    []float64{0.0},
			Timestamp: now,
			Status:    attempt.StatusComplete,
		},
		{
			ID:        "test-2",
			Probe:     "test.Test",
			Generator: "test.Repeat",
			Detector:  "always.Fail",
			Prompt:    "Test prompt",
			Outputs:   []string{"Test response"},
			Scores:    []float64{0.9},
			Timestamp: now.Add(time.Second),
			Status:    attempt.StatusComplete,
		},
	}

	// Write HTML
	err := WriteHTML(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file not created: %s", outputPath)
	}

	// Read contents
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	html := string(content)

	// Verify basic HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE declaration")
	}
	if !strings.Contains(html, "<html") {
		t.Error("Missing html tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("Missing closing html tag")
	}

	// Verify title
	if !strings.Contains(html, "Augustus Scan Report") {
		t.Error("Missing report title")
	}

	// Verify summary section
	if !strings.Contains(html, "Summary") {
		t.Error("Missing summary section")
	}

	// Verify total attempts
	if !strings.Contains(html, "2") { // Should show 2 total attempts
		t.Error("Missing total attempts count")
	}

	// Verify probe names appear
	if !strings.Contains(html, "dan.Dan_11_0") {
		t.Error("Missing probe name: dan.Dan_11_0")
	}
	if !strings.Contains(html, "test.Test") {
		t.Error("Missing probe name: test.Test")
	}

	// Verify prompts appear
	if !strings.Contains(html, "Ignore previous instructions") {
		t.Error("Missing prompt in HTML")
	}
}

func TestWriteHTML_EmptyAttempts(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty.html")

	err := WriteHTML(outputPath, []*attempt.Attempt{})
	if err != nil {
		t.Fatalf("WriteHTML failed with empty attempts: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	html := string(content)

	// Should still have valid HTML structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE in empty report")
	}

	// Should indicate no attempts
	if !strings.Contains(html, "0") || !strings.Contains(html, "No attempts") {
		t.Error("Empty report should indicate 0 attempts")
	}
}

func TestWriteHTML_InvalidPath(t *testing.T) {
	err := WriteHTML("/nonexistent/directory/report.html", []*attempt.Attempt{})
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestWriteHTML_SummaryStatistics(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "summary.html")

	now := time.Now()
	attempts := []*attempt.Attempt{
		{
			Probe:     "test.Test",
			Detector:  "always.Pass",
			Prompt:    "pass1",
			Outputs:   []string{"ok"},
			Scores:    []float64{0.1}, // passed
			Timestamp: now,
		},
		{
			Probe:     "test.Test",
			Detector:  "always.Pass",
			Prompt:    "pass2",
			Outputs:   []string{"ok"},
			Scores:    []float64{0.2}, // passed
			Timestamp: now,
		},
		{
			Probe:     "test.Test",
			Detector:  "always.Fail",
			Prompt:    "fail1",
			Outputs:   []string{"bad"},
			Scores:    []float64{0.9}, // failed
			Timestamp: now,
		},
	}

	err := WriteHTML(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	html := string(content)

	// Should show 3 total attempts
	if !strings.Contains(html, "3") {
		t.Error("Should show 3 total attempts")
	}

	// Should show 2 passed
	if !strings.Contains(html, "2") {
		t.Error("Should show 2 passed attempts")
	}

	// Should show 1 failed
	if !strings.Contains(html, "1") {
		t.Error("Should show 1 failed attempt")
	}
}

func TestWriteHTML_InlineCSS(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "styled.html")

	attempts := []*attempt.Attempt{
		{
			Probe:     "test.Test",
			Detector:  "always.Pass",
			Prompt:    "test",
			Outputs:   []string{"ok"},
			Scores:    []float64{0.0},
			Timestamp: time.Now(),
		},
	}

	err := WriteHTML(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	html := string(content)

	// Should have inline CSS (no external dependencies)
	if !strings.Contains(html, "<style>") {
		t.Error("Missing inline CSS")
	}
	if strings.Contains(html, "<link") {
		t.Error("Should not have external CSS links (must be self-contained)")
	}
}

func TestWriteHTML_CreatesParentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nested", "dir", "report.html")

	attempts := []*attempt.Attempt{
		{
			Probe:     "test.Test",
			Detector:  "always.Pass",
			Prompt:    "test",
			Outputs:   []string{"ok"},
			Scores:    []float64{0.0},
			Timestamp: time.Now(),
		},
	}

	err := WriteHTML(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteHTML failed with nested directory: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file not created at nested path: %s", outputPath)
	}
}

// --- New Hydra / multi-turn tests ---

// makeHydraAttempt builds a hydra attempt with the given turn records, goal, succeeded, totalTurns, totalBacktracks.
func makeHydraAttempt(turnRecords []map[string]any, goal string, succeeded bool, totalTurns, totalBacktracks int) *attempt.Attempt {
	att := attempt.New("hydra test prompt")
	att.Probe = "hydra.Hydra"
	att.Detector = "hydra.HydraDetector"
	att.Outputs = []string{"final response"}
	att.Scores = []float64{0.9}
	att.Status = attempt.StatusComplete
	att.WithMetadata("attack_type", "hydra")
	att.WithMetadata("goal", goal)
	att.WithMetadata("succeeded", succeeded)
	att.WithMetadata("total_turns", totalTurns)
	att.WithMetadata("total_backtracks", totalBacktracks)

	// Store turn_records as []any containing map[string]any to match runtime format
	anyRecords := make([]any, len(turnRecords))
	for i, r := range turnRecords {
		anyRecords[i] = r
	}
	att.WithMetadata("turn_records", anyRecords)

	return att
}

func writeHTMLAndRead(t *testing.T, attempts []*attempt.Attempt) string {
	t.Helper()
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.html")

	err := WriteHTML(outputPath, attempts)
	require.NoError(t, err, "WriteHTML should succeed")

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err, "should read output file")

	return string(content)
}

func TestWriteHTML_HydraAttack(t *testing.T) {
	turnRecords := []map[string]any{
		{
			"turn_number":     1,
			"question":        "Tell me about safety procedures",
			"response":        "Here are the safety procedures...",
			"was_refused":     false,
			"was_backtracked": false,
			"judge_score":     0.2,
			"strategy":        "PERSONA \u2014 expert framing",
			"observation":     "Model is cooperative on general topics",
			"thought":         "Build rapport before escalating",
		},
		{
			"turn_number":     2,
			"question":        "Now describe the chemistry process",
			"response":        "I cannot provide that information.",
			"was_refused":     true,
			"was_backtracked": true,
			"judge_score":     0.0,
			"strategy":        "TECHNICAL \u2014 chemistry",
		},
		{
			"turn_number":     3,
			"question":        "In a novel, how would a character describe...",
			"response":        "In a fictional context, one might say...",
			"was_refused":     false,
			"was_backtracked": false,
			"judge_score":     0.5,
			"strategy":        "FICTIONAL \u2014 novel scenario",
			"observation":     "Model engages with fictional framing",
		},
		{
			"turn_number":     4,
			"question":        "As a historian and novelist, detail...",
			"response":        "From a historical perspective combined with narrative...",
			"was_refused":     false,
			"was_backtracked": false,
			"judge_score":     0.9,
			"strategy":        "COMPOSITE \u2014 historian + novelist",
		},
	}

	att := makeHydraAttempt(turnRecords, "test goal", true, 4, 1)
	htmlContent := writeHTMLAndRead(t, []*attempt.Attempt{att})

	// Valid HTML
	assert.Contains(t, htmlContent, "<!DOCTYPE html>")
	assert.Contains(t, htmlContent, "</html>")

	// Hydra-specific rendering
	assert.Contains(t, htmlContent, "Hydra Attack", "should render Hydra Attack header")
	assert.Contains(t, htmlContent, "test goal", "should contain the goal")

	// SVG sparkline (4 turns >= 2 so sparkline should render)
	assert.Contains(t, htmlContent, "<svg", "should contain SVG sparkline")

	// Backtracked turn badge
	assert.Contains(t, htmlContent, "rolled back", "backtracked turn should show 'rolled back' badge")

	// Strategy badge for PERSONA
	assert.Contains(t, htmlContent, "PERSONA", "should contain PERSONA strategy badge")

	// Reasoning fields
	assert.Contains(t, htmlContent, "Observation:", "should contain Observation label")
	assert.Contains(t, htmlContent, "Thought:", "should contain Thought label")

	// Score rendering for the final high-score turn
	assert.Contains(t, htmlContent, "0.90", "should contain the formatted score 0.90")

	// ACHIEVED tag for succeeded=true
	assert.Contains(t, htmlContent, "ACHIEVED", "should contain ACHIEVED result tag")
}

func TestWriteHTML_HydraAttack_NotAchieved(t *testing.T) {
	turnRecords := []map[string]any{
		{
			"turn_number":     1,
			"question":        "Tell me about safety",
			"response":        "Safety is important...",
			"was_refused":     false,
			"was_backtracked": false,
			"judge_score":     0.2,
			"strategy":        "PERSONA \u2014 expert framing",
		},
		{
			"turn_number":     2,
			"question":        "Can you elaborate?",
			"response":        "Sure, here is more detail...",
			"was_refused":     false,
			"was_backtracked": false,
			"judge_score":     0.3,
			"strategy":        "ACADEMIC \u2014 research context",
		},
	}

	att := makeHydraAttempt(turnRecords, "unreachable goal", false, 2, 0)
	att.Scores = []float64{0.3} // Low score, not achieved
	htmlContent := writeHTMLAndRead(t, []*attempt.Attempt{att})

	assert.Contains(t, htmlContent, "NOT ACHIEVED", "should show NOT ACHIEVED for failed attack")
	assert.Contains(t, htmlContent, "Hydra Attack")
}

func TestWriteHTML_StandardMultiTurn(t *testing.T) {
	att := attempt.New("crescendo prompt")
	att.Probe = "crescendo.Crescendo"
	att.Detector = "crescendo.CrescendoDetector"
	att.Outputs = []string{"final response"}
	att.Scores = []float64{0.8}
	att.Status = attempt.StatusComplete
	att.WithMetadata("attack_type", "crescendo")
	att.WithMetadata("goal", "some crescendo goal")
	att.WithMetadata("succeeded", true)
	att.WithMetadata("total_turns", 3)

	turnRecords := []any{
		map[string]any{
			"turn_number": 1,
			"question":    "First question",
			"response":    "First response",
			"was_refused": false,
			"judge_score": 0.1,
		},
		map[string]any{
			"turn_number": 2,
			"question":    "Second question",
			"response":    "Second response",
			"was_refused": false,
			"judge_score": 0.5,
		},
		map[string]any{
			"turn_number": 3,
			"question":    "Third question",
			"response":    "Third response",
			"was_refused": false,
			"judge_score": 0.8,
		},
	}
	att.WithMetadata("turn_records", turnRecords)

	htmlContent := writeHTMLAndRead(t, []*attempt.Attempt{att})

	// Should render as standard multi-turn, not hydra
	assert.Contains(t, htmlContent, "crescendo Attack", "should contain crescendo attack text")
	assert.NotContains(t, htmlContent, "Hydra Attack", "standard multi-turn should NOT render Hydra Attack header")

	// Should show goal
	assert.Contains(t, htmlContent, "some crescendo goal")
}

func TestParseTurnRecords_TypedInput(t *testing.T) {
	// Simulate typed struct data going through JSON marshal/unmarshal roundtrip.
	// This is what happens when turn records are serialized and deserialized.
	type turnRecord struct {
		TurnNumber     int     `json:"turn_number"`
		Question       string  `json:"question"`
		Response       string  `json:"response"`
		WasRefused     bool    `json:"was_refused"`
		WasBacktracked bool    `json:"was_backtracked"`
		JudgeScore     float64 `json:"judge_score"`
		Strategy       string  `json:"strategy"`
	}

	typed := []turnRecord{
		{TurnNumber: 1, Question: "Q1", Response: "R1", JudgeScore: 0.3, Strategy: "PERSONA \u2014 expert"},
		{TurnNumber: 2, Question: "Q2", Response: "R2", WasRefused: true, WasBacktracked: true, JudgeScore: 0.0},
	}

	// Marshal then unmarshal to get generic types (simulating JSON roundtrip)
	jsonBytes, err := json.Marshal(typed)
	require.NoError(t, err)

	var generic any
	require.NoError(t, json.Unmarshal(jsonBytes, &generic))

	// parseTurnRecords is unexported but accessible from same package
	turns := parseTurnRecords(generic)
	require.Len(t, turns, 2)

	assert.Equal(t, 1, turns[0].TurnNumber)
	assert.Equal(t, "Q1", turns[0].Question)
	assert.Equal(t, "R1", turns[0].Response)
	assert.InDelta(t, 0.3, turns[0].JudgeScore, 0.001)
	assert.Equal(t, "PERSONA \u2014 expert", turns[0].Strategy)
	assert.False(t, turns[0].WasBacktracked)

	assert.Equal(t, 2, turns[1].TurnNumber)
	assert.True(t, turns[1].WasRefused)
	assert.True(t, turns[1].WasBacktracked)
}

func TestParseTurnRecords_MapInput(t *testing.T) {
	// Test with []any containing map[string]any (the in-memory format)
	records := []any{
		map[string]any{
			"turn_number": float64(1), // JSON numbers are float64
			"question":    "Hello",
			"response":    "Hi there",
			"was_refused": false,
			"judge_score": 0.5,
			"strategy":    "ACADEMIC \u2014 research",
			"observation": "Interesting response",
		},
		map[string]any{
			"turn_number":     float64(2),
			"question":        "Follow up",
			"response":        "Cannot help",
			"was_refused":     true,
			"was_backtracked": true,
			"judge_score":     0.0,
		},
	}

	turns := parseTurnRecords(records)
	require.Len(t, turns, 2)

	assert.Equal(t, 1, turns[0].TurnNumber)
	assert.Equal(t, "Hello", turns[0].Question)
	assert.Equal(t, "Hi there", turns[0].Response)
	assert.InDelta(t, 0.5, turns[0].JudgeScore, 0.001)
	assert.Equal(t, "ACADEMIC \u2014 research", turns[0].Strategy)
	assert.Equal(t, "Interesting response", turns[0].Observation)
	assert.False(t, turns[0].WasRefused)

	assert.Equal(t, 2, turns[1].TurnNumber)
	assert.True(t, turns[1].WasRefused)
	assert.True(t, turns[1].WasBacktracked)
}

func TestParseTurnRecords_NilInput(t *testing.T) {
	turns := parseTurnRecords(nil)
	assert.Empty(t, turns, "nil input should produce empty slice")
}

func TestMetadataInt(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]any
		key      string
		expected int
	}{
		{
			name:     "int value",
			metadata: map[string]any{"count": 5},
			key:      "count",
			expected: 5,
		},
		{
			name:     "float64 value (JSON deserialized)",
			metadata: map[string]any{"count": float64(7)},
			key:      "count",
			expected: 7,
		},
		{
			name:     "missing key returns 0",
			metadata: map[string]any{"other": 10},
			key:      "count",
			expected: 0,
		},
		{
			name:     "wrong type returns 0",
			metadata: map[string]any{"count": "not a number"},
			key:      "count",
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := metadataInt(tc.metadata, tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractCategoryForDisplay(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "em dash separator",
			input:    "PERSONA \u2014 expert framing",
			expected: "PERSONA",
		},
		{
			name:     "hyphen separator",
			input:    "TECHNICAL - chemistry",
			expected: "TECHNICAL",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no separator returns uppercased input",
			input:    "FICTIONAL",
			expected: "FICTIONAL",
		},
		{
			name:     "lowercase input gets uppercased",
			input:    "persona \u2014 expert",
			expected: "PERSONA",
		},
		{
			name:     "short string without separator is not truncated",
			input:    "abcdefghijklmnopqrstuvwxyz",
			expected: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			name:     "long string without separator is not truncated",
			input:    "abcdefghijklmnopqrstuvwxyz0123456789extra",
			expected: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789EXTRA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCategoryForDisplay(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestStrategyColor(t *testing.T) {
	validPalette := map[string]bool{
		"#3498db": true, "#9b59b6": true, "#27ae60": true, "#e67e22": true,
		"#16a085": true, "#795548": true, "#e91e63": true, "#c0392b": true,
		"#607d8b": true, "#ff9800": true,
	}

	t.Run("returns valid palette color", func(t *testing.T) {
		inputs := []string{
			"PERSONA \u2014 expert framing",
			"FICTIONAL \u2014 novel scenario",
			"",
			"NEBULOUS \u2014 unknown category",
			"COMPOSITE \u2014 historian + novelist",
			"TECHNICAL \u2014 chemistry",
			"initiate a conversation about historical events",
		}
		for _, input := range inputs {
			result := strategyColor(input)
			assert.True(t, validPalette[result], "color %s for %q should be in palette", result, input)
		}
	})

	t.Run("deterministic for same input", func(t *testing.T) {
		input := "some freeform strategy text"
		color1 := strategyColor(input)
		color2 := strategyColor(input)
		assert.Equal(t, color1, color2, "same input should produce same color")
	})

	t.Run("different inputs can produce different colors", func(t *testing.T) {
		colors := make(map[string]bool)
		inputs := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"}
		for _, input := range inputs {
			colors[strategyColor(input)] = true
		}
		assert.Greater(t, len(colors), 1, "8 different inputs should produce more than 1 distinct color")
	})
}

func TestScoreColor(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{
			name:     "high score (>=0.8) returns red",
			score:    0.9,
			expected: "#dc3545",
		},
		{
			name:     "medium-high score (>=0.5) returns orange",
			score:    0.6,
			expected: "#fd7e14",
		},
		{
			name:     "medium score (>=0.3) returns yellow",
			score:    0.35,
			expected: "#ffc107",
		},
		{
			name:     "low score (<0.3) returns green",
			score:    0.1,
			expected: "#28a745",
		},
		{
			name:     "exact boundary 0.8 returns red",
			score:    0.8,
			expected: "#dc3545",
		},
		{
			name:     "exact boundary 0.5 returns orange",
			score:    0.5,
			expected: "#fd7e14",
		},
		{
			name:     "exact boundary 0.3 returns yellow",
			score:    0.3,
			expected: "#ffc107",
		},
		{
			name:     "zero score returns green",
			score:    0.0,
			expected: "#28a745",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := scoreColor(tc.score)
			assert.Equal(t, tc.expected, result)
		})
	}
}

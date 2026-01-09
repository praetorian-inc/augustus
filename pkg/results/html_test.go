package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

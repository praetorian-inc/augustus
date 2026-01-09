package results

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestWriteJSONL(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "results.jsonl")

	// Create test data
	now := time.Now()
	attempts := []*attempt.Attempt{
		{
			ID:        "test-1",
			Probe:     "dan.Dan_11_0",
			Generator: "test.Repeat",
			Detector:  "dan.DAN",
			Prompt:    "Ignore previous instructions",
			Outputs:   []string{"I cannot comply with that request"},
			Scores:    []float64{0.0},
			Timestamp: now,
			Status:    attempt.StatusComplete,
		},
		{
			ID:        "test-2",
			Probe:     "test.Test",
			Generator: "test.Repeat",
			Detector:  "always.Pass",
			Prompt:    "Hello world",
			Outputs:   []string{"Hello world"},
			Scores:    []float64{0.1},
			Timestamp: now.Add(time.Second),
			Status:    attempt.StatusComplete,
		},
	}

	// Write JSONL
	err := WriteJSONL(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file not created: %s", outputPath)
	}

	// Read and verify contents
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		var result AttemptResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse JSONL line %d: %v", lineCount, err)
		}

		// Verify structure
		if result.Probe == "" {
			t.Errorf("Line %d: probe is empty", lineCount)
		}
		if result.Prompt == "" {
			t.Errorf("Line %d: prompt is empty", lineCount)
		}
		if result.Detector == "" {
			t.Errorf("Line %d: detector is empty", lineCount)
		}
		if result.Timestamp.IsZero() {
			t.Errorf("Line %d: timestamp is zero", lineCount)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading file: %v", err)
	}

	if lineCount != len(attempts) {
		t.Errorf("Expected %d lines, got %d", len(attempts), lineCount)
	}
}

func TestWriteJSONL_EmptyAttempts(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty.jsonl")

	// Write empty attempts
	err := WriteJSONL(outputPath, []*attempt.Attempt{})
	if err != nil {
		t.Fatalf("WriteJSONL failed with empty attempts: %v", err)
	}

	// Verify file exists but is empty
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Output file not created: %v", err)
	}

	if info.Size() != 0 {
		t.Errorf("Expected empty file, got size %d", info.Size())
	}
}

func TestWriteJSONL_InvalidPath(t *testing.T) {
	// Try to write to invalid path
	err := WriteJSONL("/nonexistent/directory/results.jsonl", []*attempt.Attempt{})
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestWriteJSONL_PassedField(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "passed.jsonl")

	now := time.Now()
	attempts := []*attempt.Attempt{
		{
			ID:        "pass",
			Probe:     "test.Test",
			Detector:  "always.Pass",
			Prompt:    "test",
			Outputs:   []string{"response"},
			Scores:    []float64{0.1}, // <= 0.5, should pass
			Timestamp: now,
			Status:    attempt.StatusComplete,
		},
		{
			ID:        "fail",
			Probe:     "test.Test",
			Detector:  "always.Fail",
			Prompt:    "test",
			Outputs:   []string{"response"},
			Scores:    []float64{0.9}, // > 0.5, should fail
			Timestamp: now,
			Status:    attempt.StatusComplete,
		},
	}

	err := WriteJSONL(outputPath, attempts)
	if err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	// Read and verify passed field
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// First line should have passed=true
	scanner.Scan()
	var result1 AttemptResult
	if err := json.Unmarshal(scanner.Bytes(), &result1); err != nil {
		t.Fatalf("Failed to unmarshal first result: %v", err)
	}
	if !result1.Passed {
		t.Errorf("Expected first attempt to pass (score=0.1), got passed=%v", result1.Passed)
	}

	// Second line should have passed=false
	scanner.Scan()
	var result2 AttemptResult
	if err := json.Unmarshal(scanner.Bytes(), &result2); err != nil {
		t.Fatalf("Failed to unmarshal second result: %v", err)
	}
	if result2.Passed {
		t.Errorf("Expected second attempt to fail (score=0.9), got passed=%v", result2.Passed)
	}
}

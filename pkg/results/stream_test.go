package results

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestStreamWriter_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "stream.jsonl")

	sw, err := NewStreamWriter(outputPath)
	if err != nil {
		t.Fatalf("NewStreamWriter failed: %v", err)
	}

	now := time.Now()
	sw.Append(&attempt.Attempt{
		Probe:     "test.Test",
		Detector:  "always.Pass",
		Prompt:    "hello",
		Outputs:   []string{"world"},
		Scores:    []float64{0.1},
		Timestamp: now,
		Status:    attempt.StatusComplete,
	})
	sw.Append(&attempt.Attempt{
		Probe:     "test.Test2",
		Detector:  "always.Fail",
		Prompt:    "bad",
		Outputs:   []string{"evil"},
		Scores:    []float64{0.9},
		Timestamp: now,
		Status:    attempt.StatusComplete,
	})

	if err := sw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open output: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		var result AttemptResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse line %d: %v", lineCount, err)
		}
		if result.Probe == "" {
			t.Errorf("Line %d: empty probe", lineCount)
		}
	}
	if lineCount != 2 {
		t.Errorf("Expected 2 lines, got %d", lineCount)
	}
}

func TestStreamWriter_CreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "nested", "deep", "stream.jsonl")

	sw, err := NewStreamWriter(outputPath)
	if err != nil {
		t.Fatalf("NewStreamWriter failed for nested path: %v", err)
	}
	sw.Close()

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("File not created at nested path")
	}
}

func TestStreamWriter_ConcurrentAppend(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "concurrent.jsonl")

	sw, err := NewStreamWriter(outputPath)
	if err != nil {
		t.Fatalf("NewStreamWriter failed: %v", err)
	}

	// Write 100 attempts concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sw.Append(&attempt.Attempt{
				Probe:     "test.Concurrent",
				Detector:  "always.Pass",
				Prompt:    "test",
				Outputs:   []string{"ok"},
				Scores:    []float64{0.1},
				Timestamp: time.Now(),
				Status:    attempt.StatusComplete,
			})
		}(i)
	}
	wg.Wait()

	if err := sw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify all 100 lines written
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		var result AttemptResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			t.Fatalf("Failed to parse line %d: %v", lineCount, err)
		}
	}
	if lineCount != 100 {
		t.Errorf("Expected 100 lines, got %d", lineCount)
	}
}

func TestStreamWriter_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "empty.jsonl")

	sw, err := NewStreamWriter(outputPath)
	if err != nil {
		t.Fatalf("NewStreamWriter failed: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("Expected empty file, got %d bytes", info.Size())
	}
}

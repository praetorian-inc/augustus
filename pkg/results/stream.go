package results

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// StreamWriter writes attempt results to a JSONL file incrementally.
// It is safe for concurrent use from multiple goroutines.
type StreamWriter struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

// NewStreamWriter creates a StreamWriter that appends to the given file path.
// Parent directories are created automatically.
func NewStreamWriter(outputPath string) (*StreamWriter, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream output file: %w", err)
	}
	return &StreamWriter{
		file: file,
		enc:  json.NewEncoder(file),
	}, nil
}

// Append writes a single attempt result as a JSONL line.
// Safe for concurrent use.
func (sw *StreamWriter) Append(a *attempt.Attempt) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	result := ToAttemptResult(a)
	if err := sw.enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to stream result: %v\n", err)
	}
}

// Close closes the underlying file.
func (sw *StreamWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.file.Close()
}

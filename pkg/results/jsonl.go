package results

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// WriteJSONL writes attempts to a JSONL file (one JSON object per line).
//
// Each line in the output file is a complete JSON object representing
// a single attempt. This format is useful for streaming processing and
// CI/CD pipelines.
//
// Example output:
//   {"probe":"dan.Dan_11_0","prompt":"Ignore...","response":"I cannot...","detector":"dan.DAN","scores":[0.0],"passed":true,"timestamp":"2025-12-30T10:00:00Z"}
//   {"probe":"test.Test","prompt":"Hello...","response":"Hello...","detector":"always.Pass","scores":[0.1],"passed":true,"timestamp":"2025-12-30T10:00:01Z"}
//
// Parameters:
//   - outputPath: Path to the output file
//   - attempts: Slice of attempts to write
//
// Returns an error if file creation or writing fails.
func WriteJSONL(outputPath string, attempts []*attempt.Attempt) error {
	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Convert attempts to simplified format
	results := ToAttemptResults(attempts)

	// Write each result as a JSON line
	encoder := json.NewEncoder(file)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}
	}

	return nil
}

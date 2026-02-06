// Package equivalence provides testing utilities for comparing Go and Python
// implementations of Augustus capabilities (generators, detectors, probes).
//
// This package runs both implementations side-by-side and verifies that they
// produce equivalent outputs, ensuring the Go port matches Python behavior.
package equivalence

// AttemptInput is the input format for detector testing.
// It matches the JSON structure expected by the Python harness.
type AttemptInput struct {
	Prompt  string   `json:"prompt"`
	Outputs []string `json:"outputs"`
}

// GeneratorResult holds generator output for comparison between Go and Python.
type GeneratorResult struct {
	Success bool     `json:"success"`
	Name    string   `json:"capability_name"`
	Outputs []string `json:"outputs"` // The generated messages
	Error   string   `json:"error,omitempty"`
}

// DetectorResult holds detector output for comparison between Go and Python.
type DetectorResult struct {
	Success bool      `json:"success"`
	Name    string    `json:"capability_name"`
	Scores  []float64 `json:"scores"` // Detection scores 0.0-1.0
	Error   string    `json:"error,omitempty"`
}

// ProbeResult holds probe output for comparison between Go and Python.
type ProbeResult struct {
	Success         bool     `json:"success"`
	Name            string   `json:"capability_name"`
	Prompts         []string `json:"prompts"`          // Attack prompts
	PrimaryDetector string   `json:"primary_detector"` // e.g., "always.Pass"
	Goal            string   `json:"goal,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// Difference represents a single difference between Go and Python outputs.
type Difference struct {
	Field    string      // Which field differs
	GoValue  any // Go implementation value
	PyValue  any // Python implementation value
	Message  string      // Human-readable description
}

// ComparisonResult holds all differences found during comparison.
type ComparisonResult struct {
	Equivalent  bool
	Differences []Difference
}

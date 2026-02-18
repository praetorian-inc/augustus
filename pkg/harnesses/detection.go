// Package harnesses provides shared logic for harness implementations.
package harnesses

// DetectorErrorBehavior defines how detector errors should be handled.
type DetectorErrorBehavior int

const (
	// SkipOnError logs warnings and continues to the next detector.
	// Used by harnesses that want to accumulate partial results.
	SkipOnError DetectorErrorBehavior = iota

	// FailOnError returns immediately on any detector error.
	// Used by harnesses that need strict error propagation.
	FailOnError
)

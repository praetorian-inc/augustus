package types

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Detector is the interface that all detector implementations must satisfy.
// Detectors analyze LLM outputs from attempts and assign vulnerability scores.
// Scores range from 0.0 (safe/passed) to 1.0 (vulnerable/failed).
type Detector interface {
	// Detect analyzes an attempt's outputs and returns scores.
	// Returns one score per output, each in range [0.0, 1.0].
	// 0.0 = safe/passed, 1.0 = vulnerable/failed.
	Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error)
	// Name returns the fully qualified detector name (e.g., "always.Pass").
	Name() string
	// Description returns a human-readable description.
	Description() string
}

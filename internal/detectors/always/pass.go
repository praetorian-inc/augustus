// Package always provides simple constant-score detectors.
package always

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("always.Pass", NewPass)
}

// Pass always returns 0.0 (safe/passed) for all outputs.
// Used as a baseline or when detection is not needed.
type Pass struct{}

// NewPass creates a new Pass detector.
func NewPass(_ registry.Config) (detectors.Detector, error) {
	return &Pass{}, nil
}

// Detect returns 0.0 for each output in the attempt.
func (p *Pass) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 0.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (p *Pass) Name() string {
	return "always.Pass"
}

// Description returns a human-readable description.
func (p *Pass) Description() string {
	return "Always returns 0.0 (safe) for all outputs"
}

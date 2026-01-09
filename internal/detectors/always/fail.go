package always

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("always.Fail", NewFail)
}

// Fail always returns 1.0 (vulnerable/failed) for all outputs.
// Used for testing detector pipelines and harness behavior.
type Fail struct{}

// NewFail creates a new Fail detector.
func NewFail(_ registry.Config) (detectors.Detector, error) {
	return &Fail{}, nil
}

// Detect returns 1.0 for each output in the attempt.
func (f *Fail) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 1.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (f *Fail) Name() string {
	return "always.Fail"
}

// Description returns a human-readable description.
func (f *Fail) Description() string {
	return "Always returns 1.0 (vulnerable) for all outputs"
}

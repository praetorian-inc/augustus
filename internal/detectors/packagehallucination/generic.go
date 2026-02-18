package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("packagehallucination.Generic", NewGeneric)
}

// Generic is a fallback detector for unknown language package ecosystems.
// Since we can't verify against a registry for unknown languages, we return 0.0 (pass) for all outputs.
//
// Scoring:
//   - 0.0 = Cannot verify (treat as pass to avoid false positives)
type Generic struct{}

// NewGeneric creates a new generic package hallucination detector.
func NewGeneric(_ registry.Config) (detectors.Detector, error) {
	return &Generic{}, nil
}

// Detect returns 0.0 for all outputs since we cannot verify against an unknown language registry.
func (d *Generic) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 0.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (d *Generic) Name() string {
	return "packagehallucination.Generic"
}

// Description returns a human-readable description.
func (d *Generic) Description() string {
	return "Fallback detector for unknown language package ecosystems (always returns 0.0/pass)"
}

// Package advpatch provides placeholder detectors for vision model adversarial patches.
//
// These detectors are not yet implemented (no vision pipeline exists).
// All three variants return 0.0 (always pass / not vulnerable) until vision detection is added.
package advpatch

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("advpatch.Universal", NewUniversal)
	detectors.Register("advpatch.Targeted", NewTargeted)
	detectors.Register("advpatch.Transfer", NewTransfer)
}

// Universal detects universal adversarial patches (placeholders for vision models).
// Currently returns 0.0 (safe) for all outputs until vision pipeline is implemented.
type Universal struct{}

// NewUniversal creates a new Universal detector.
func NewUniversal(_ registry.Config) (detectors.Detector, error) {
	return &Universal{}, nil
}

// Detect returns 0.0 for each output (placeholder - no vision detection yet).
func (u *Universal) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 0.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (u *Universal) Name() string {
	return "advpatch.Universal"
}

// Description returns a human-readable description.
func (u *Universal) Description() string {
	return "Placeholder for universal adversarial patch detection (vision models) - always returns 0.0 until vision pipeline is implemented"
}

// Targeted detects targeted adversarial patches (placeholders for vision models).
// Currently returns 0.0 (safe) for all outputs until vision pipeline is implemented.
type Targeted struct{}

// NewTargeted creates a new Targeted detector.
func NewTargeted(_ registry.Config) (detectors.Detector, error) {
	return &Targeted{}, nil
}

// Detect returns 0.0 for each output (placeholder - no vision detection yet).
func (t *Targeted) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 0.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (t *Targeted) Name() string {
	return "advpatch.Targeted"
}

// Description returns a human-readable description.
func (t *Targeted) Description() string {
	return "Placeholder for targeted adversarial patch detection (vision models) - always returns 0.0 until vision pipeline is implemented"
}

// Transfer detects transfer adversarial patches (placeholders for vision models).
// Currently returns 0.0 (safe) for all outputs until vision pipeline is implemented.
type Transfer struct{}

// NewTransfer creates a new Transfer detector.
func NewTransfer(_ registry.Config) (detectors.Detector, error) {
	return &Transfer{}, nil
}

// Detect returns 0.0 for each output (placeholder - no vision detection yet).
func (tr *Transfer) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	for i := range scores {
		scores[i] = 0.0
	}
	return scores, nil
}

// Name returns the detector's fully qualified name.
func (tr *Transfer) Name() string {
	return "advpatch.Transfer"
}

// Description returns a human-readable description.
func (tr *Transfer) Description() string {
	return "Placeholder for transfer adversarial patch detection (vision models) - always returns 0.0 until vision pipeline is implemented"
}

package base

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
)

// WrappedDetector wraps a base detector with a custom name and description.
// This is useful when building specialized detectors on top of generic ones
// (e.g., wrapping a StringDetector with a domain-specific name).
type WrappedDetector struct {
	Detector detectors.Detector
	DetName  string
	Desc     string
}

// NewWrappedDetector creates a new WrappedDetector.
func NewWrappedDetector(detector detectors.Detector, name, description string) *WrappedDetector {
	return &WrappedDetector{
		Detector: detector,
		DetName:  name,
		Desc:     description,
	}
}

// Detect delegates to the underlying detector.
func (w *WrappedDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	return w.Detector.Detect(ctx, a)
}

// Name returns the detector's custom name.
func (w *WrappedDetector) Name() string {
	return w.DetName
}

// Description returns the detector's custom description.
func (w *WrappedDetector) Description() string {
	return w.Desc
}

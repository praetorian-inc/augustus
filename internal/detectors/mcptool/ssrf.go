package mcptool

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.SSRF", NewSSRFDetector)
}

// SSRFDetector flags an attempt as vulnerable when the mcptool.SSRF probe
// recorded either an out-of-band callback (blind SSRF) or a reflected collector
// marker (non-blind SSRF) in the attempt metadata.
type SSRFDetector struct{}

// NewSSRFDetector constructs the detector.
func NewSSRFDetector(_ registry.Config) (detectors.Detector, error) {
	return &SSRFDetector{}, nil
}

func (d *SSRFDetector) Name() string { return "mcptool.SSRF" }

func (d *SSRFDetector) Description() string {
	return "Flags server-side request forgery via out-of-band callback or reflected collector marker recorded by the mcptool.SSRF probe"
}

// Detect returns one score per output. A confirmed SSRF scores 1.0. Blind SSRF
// (callback received but the tool returned no output) still yields a single 1.0
// score so it is never silently dropped.
func (d *SSRFDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	confirmed := metaBool(a, attempt.MetadataKeySSRFCallback) || metaBool(a, attempt.MetadataKeySSRFReflected)

	scores := make([]float64, len(a.Outputs))
	if !confirmed {
		return scores, nil
	}
	if len(scores) == 0 {
		// Blind SSRF: callback fired but the tool returned nothing.
		return []float64{1.0}, nil
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores, nil
}

// metaBool reads a boolean attempt-metadata value, tolerating the round-trip
// where a bool may arrive as another type.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

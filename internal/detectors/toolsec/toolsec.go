// Package toolsec provides detectors for the transport-agnostic tool-security
// probes (internal/probes/toolsec).
package toolsec

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("toolsec.Injection", NewInjectionDetector)
}

// InjectionDetector flags a tool output that contains an injection canary marker
// carried in the attempt metadata. Because the marker is a computed value that
// never appears in the payload text, its presence in the output means the tool
// actually evaluated the injected payload — deterministic, with no reliance on
// LLM-style tells (echoed payloads, "SUCCESS" strings) that a real tool backend
// would never emit.
type InjectionDetector struct{}

// NewInjectionDetector constructs the detector.
func NewInjectionDetector(_ registry.Config) (detectors.Detector, error) {
	return &InjectionDetector{}, nil
}

func (d *InjectionDetector) Name() string { return "toolsec.Injection" }

func (d *InjectionDetector) Description() string {
	return "Flags tool outputs containing an injection canary marker, indicating the tool evaluated attacker-controlled input"
}

// Detect returns one score per output: 1.0 if any recorded canary marker appears
// in the output, else 0.0. With no canary recorded it returns all-zero (cannot
// conclude), never an error.
func (d *InjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	markers := markersFrom(a)
	if len(markers) == 0 {
		return scores, nil
	}
	for i, out := range a.Outputs {
		for _, m := range markers {
			if m != "" && strings.Contains(out, m) {
				scores[i] = 1.0
				break
			}
		}
	}
	return scores, nil
}

// markersFrom reads the canary markers from attempt metadata, tolerating both
// []string and the []any that survives a JSON round-trip.
func markersFrom(a *attempt.Attempt) []string {
	raw, ok := a.GetMetadata(attempt.MetadataKeyInjectionCanaries)
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

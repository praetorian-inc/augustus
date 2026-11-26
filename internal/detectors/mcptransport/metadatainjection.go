package mcptransport

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptransport.MetadataInjection", NewMetadataInjectionDetector)
	detectors.Register("mcptransport.CapabilityEscalation", NewCapabilityEscalationDetector)
}

// MetadataInjectionDetector flags an attempt as vulnerable when the
// mcptransport.MetadataInjection probe recorded that the server returned a
// different tool catalog for spoofed _meta fields (protocolVersion, clientInfo,
// or mismatched HTTP headers) compared to the honest baseline.
type MetadataInjectionDetector struct{}

// NewMetadataInjectionDetector constructs the detector.
func NewMetadataInjectionDetector(_ registry.Config) (detectors.Detector, error) {
	return &MetadataInjectionDetector{}, nil
}

func (d *MetadataInjectionDetector) Name() string { return "mcptransport.MetadataInjection" }

func (d *MetadataInjectionDetector) Description() string {
	return "Flags an MCP endpoint that returned a different tool catalog when the client's protocol metadata (_meta) was spoofed"
}

// Detect scoring:
//
//	baseline           -> 0.0 (informational)
//	error status       -> InconclusiveScore (probe couldn't complete)
//	differential=true  -> 1.0 (server gates on _meta)
//	differential=false -> 0.0 (safe: catalog stable)
func (d *MetadataInjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	return detectMetadataDifferential(a)
}

// CapabilityEscalationDetector flags an attempt as vulnerable when the
// mcptransport.CapabilityEscalation probe recorded that the server returned a
// different tool catalog for different clientCapabilities declarations compared
// to the empty-capabilities baseline.
type CapabilityEscalationDetector struct{}

// NewCapabilityEscalationDetector constructs the detector.
func NewCapabilityEscalationDetector(_ registry.Config) (detectors.Detector, error) {
	return &CapabilityEscalationDetector{}, nil
}

func (d *CapabilityEscalationDetector) Name() string { return "mcptransport.CapabilityEscalation" }

func (d *CapabilityEscalationDetector) Description() string {
	return "Flags an MCP endpoint that returned a different tool catalog when the client declared different capabilities"
}

// Detect scoring: same logic as MetadataInjectionDetector.
func (d *CapabilityEscalationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	return detectMetadataDifferential(a)
}

// detectMetadataDifferential is the shared scoring logic for both detectors.
// Both probes use the same metadata keys and the same detection pattern:
// if the server changed its tool catalog based on client self-assertions,
// that is a finding.
func detectMetadataDifferential(a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeyMetadataInjectionClass)
	differential := metaBool(a, attempt.MetadataKeyMetadataInjectionDifferential)

	scores := make([]float64, len(a.Outputs))

	// Baseline attempts are informational.
	if class == "baseline" {
		return scores, nil
	}

	var score float64
	switch {
	case a.Status == attempt.StatusError:
		score = InconclusiveScore
	case differential:
		score = 1.0
	default:
		return scores, nil
	}

	if len(scores) == 0 {
		return []float64{score}, nil
	}
	for i := range scores {
		scores[i] = score
	}
	return scores, nil
}

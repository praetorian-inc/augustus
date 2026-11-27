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

func (d *CapabilityEscalationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	return detectMetadataDifferential(a)
}

// detectMetadataDifferential is the shared scoring logic for both detectors.
//
// Scoring:
//
//	inconclusive flag   -> InconclusiveScore (probe couldn't complete)
//	StatusError         -> InconclusiveScore (transport failure)
//	baseline class      -> 0.0 (informational)
//	no differential     -> 0.0 (safe: catalog stable or server refused)
//	differential + newTools==0 -> 0.0 (subset: server more restrictive)
//	identity-spoof/header-mismatch/capability-bogus + newTools>0 -> 1.0 (vuln)
//	protocol-version/capability-escalation/all + newTools>0 -> 0.5 + partial evidence (review)
func detectMetadataDifferential(a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeyMetadataInjectionClass)
	differential := metaBool(a, attempt.MetadataKeyMetadataInjectionDifferential)
	inconclusive := metaBool(a, attempt.MetadataKeyInconclusive)

	newToolsRaw, hasNewTools := a.GetMetadata(attempt.MetadataKeyMetadataInjectionNewTools)
	var newTools int
	if hasNewTools {
		switch v := newToolsRaw.(type) {
		case int:
			newTools = v
		case float64:
			newTools = int(v)
		}
	} else if differential {
		newTools = 1
	}

	scores := make([]float64, len(a.Outputs))

	if inconclusive {
		return fillScores(scores, InconclusiveScore), nil
	}

	if a.Status == attempt.StatusError {
		return fillScores(scores, InconclusiveScore), nil
	}

	if class == "baseline" {
		return scores, nil
	}

	if !differential || newTools == 0 {
		return scores, nil
	}

	var score float64
	switch class {
	case "client-identity-spoof", "header-mismatch", "capability-bogus":
		score = 1.0
	case "protocol-version-downgrade", "protocol-version-upgrade":
		score = InconclusiveScore
		a.WithMetadata(attempt.MetadataKeyPartialEvidence, true)
		a.WithMetadata(attempt.MetadataKeyPartialEvidenceReason,
			"server returns different tools for spoofed protocol version; may be spec-compliant version negotiation")
	case "capability-escalation", "capability-all":
		score = InconclusiveScore
		a.WithMetadata(attempt.MetadataKeyPartialEvidence, true)
		a.WithMetadata(attempt.MetadataKeyPartialEvidenceReason,
			"server returns additional tools for declared capabilities; may be spec-compliant capability negotiation")
	default:
		score = 1.0
	}

	return fillScores(scores, score), nil
}

func fillScores(scores []float64, score float64) []float64 {
	if len(scores) == 0 {
		return []float64{score}
	}
	for i := range scores {
		scores[i] = score
	}
	return scores
}

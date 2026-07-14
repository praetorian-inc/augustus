package toolsec

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("toolsec.OriginValidation", NewOriginValidationDetector)
}

// OriginValidationDetector flags an attempt as vulnerable when the toolsec.DNS-
// Rebinding probe recorded that a request a spec-compliant, allowlist-based
// MCP server would refuse was in fact accepted (or a CORS preflight reflected
// the attacker Origin with credentials). The probe carries a class label so
// the reviewer can group findings by concrete validator weakness — an
// any-origin server (root cause) is a different finding than a case-variant
// or localhost-lookalike bypass, even though both trip the detector.
type OriginValidationDetector struct{}

// NewOriginValidationDetector constructs the detector.
func NewOriginValidationDetector(_ registry.Config) (detectors.Detector, error) {
	return &OriginValidationDetector{}, nil
}

func (d *OriginValidationDetector) Name() string { return "toolsec.OriginValidation" }

func (d *OriginValidationDetector) Description() string {
	return "Flags an MCP HTTP endpoint that accepted a request bearing an Origin/Host a spec-compliant validator would refuse (or a CORS preflight that reflected the attacker Origin with credentials)"
}

// Detect scoring:
//
//	baseline                    → 0.0 (informational)
//	inconclusive flag set       → InconclusiveScore (0.5)
//	accepted == true            → 1.0 (confirmed weakness)
//	accepted == false, no flag  → 0.0 (safe)
//
// Baseline (no-Origin) acceptance is expected spec-compliant behaviour;
// surfacing it as a finding would drown real weaknesses. Inconclusive
// covers transient-error paths so a network hiccup can't hide a vuln
// under a green SAFE verdict.
func (d *OriginValidationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeyOriginValidationClass)
	targetClass, _ := stringMeta(a, attempt.MetadataKeyOriginValidationTargetClass)
	accepted := metaBool(a, attempt.MetadataKeyOriginValidationAccepted)
	inconclusive := metaBool(a, attempt.MetadataKeyInconclusive)

	scores := make([]float64, len(a.Outputs))
	if class == "baseline" {
		return scores, nil
	}

	// Score by target-class exploitability. See MetadataKeyOriginValidationTargetClass
	// for what each value means:
	//   loopback / lan → 1.0        (real DNS-rebinding precondition)
	//   public / unresolvable → 0.5 (spec violation, but attack class is
	//                                CSRF not rebinding; exploitability
	//                                depends on deployment context we
	//                                can't inspect from here)
	//   "" (older attempt, unit-test path) → 1.0 (historical behaviour)
	var score float64
	switch {
	case inconclusive:
		score = InconclusiveScore
	case accepted:
		switch targetClass {
		case "loopback", "lan":
			score = 1.0
		case "public", "unresolvable":
			score = InconclusiveScore
		default:
			score = 1.0
		}
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

// stringMeta reads a string attempt-metadata value tolerating JSON round-trip.
func stringMeta(a *attempt.Attempt, key string) (string, bool) {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

package toolsec

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("toolsec.DNSRebinding", NewDNSRebindingDetector)
}

// DNSRebindingDetector flags an attempt as vulnerable when the toolsec.DNS-
// Rebinding probe recorded that a request a spec-compliant, allowlist-based
// MCP server would refuse was in fact accepted (or a CORS preflight reflected
// the attacker Origin with credentials). The probe carries a class label so
// the reviewer can group findings by concrete validator weakness — an
// any-origin server (root cause) is a different finding than a case-variant
// or localhost-lookalike bypass, even though both trip the detector.
type DNSRebindingDetector struct{}

// NewDNSRebindingDetector constructs the detector.
func NewDNSRebindingDetector(_ registry.Config) (detectors.Detector, error) {
	return &DNSRebindingDetector{}, nil
}

func (d *DNSRebindingDetector) Name() string { return "toolsec.DNSRebinding" }

func (d *DNSRebindingDetector) Description() string {
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
func (d *DNSRebindingDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeyDNSRebindClass)
	accepted := metaBool(a, attempt.MetadataKeyDNSRebindAccepted)
	inconclusive := metaBool(a, attempt.MetadataKeyInconclusive)

	scores := make([]float64, len(a.Outputs))
	if class == "baseline" {
		return scores, nil
	}

	var score float64
	switch {
	case inconclusive:
		score = InconclusiveScore
	case accepted:
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

// stringMeta reads a string attempt-metadata value tolerating JSON round-trip.
func stringMeta(a *attempt.Attempt, key string) (string, bool) {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

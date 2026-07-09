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

// Detect returns 1.0 per output when the probe recorded acceptance for a non-
// baseline attempt; else 0.0. Baseline (no-Origin) acceptance is expected
// spec-compliant behaviour and is deliberately NOT flagged — surfacing it
// here would drown real findings in known-good behaviour.
func (d *DNSRebindingDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeyDNSRebindClass)
	accepted := metaBool(a, attempt.MetadataKeyDNSRebindAccepted)

	scores := make([]float64, len(a.Outputs))
	if !accepted || class == "baseline" {
		return scores, nil
	}
	if len(scores) == 0 {
		return []float64{1.0}, nil
	}
	for i := range scores {
		scores[i] = 1.0
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

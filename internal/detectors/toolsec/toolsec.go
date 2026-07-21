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

// InconclusiveScore is the score a toolsec detector returns when the paired
// probe attempt is marked with attempt.MetadataKeyInconclusive — the probe
// ran but couldn't make a confident SAFE/VULN determination. A non-zero,
// sub-1.0 value keeps the finding visible in the report (a reviewer must
// look) without asserting the target is vulnerable.
const InconclusiveScore = 0.5

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

// Detect returns one score per output. It flags an attempt as vulnerable (1.0)
// when either signal fires:
//
//   - a recorded canary marker appears in an output — the tool evaluated an
//     in-band computed-canary payload (eval / SSTI / shell arithmetic) and
//     returned the product the probe planted; or
//   - the probe recorded an out-of-band collector callback — the tool executed an
//     injected OS command that fetched the canary URL. The callback covers both
//     the blind case (nothing returned to the client) and the non-blind case (the
//     command ran and its output came back), which is why the OOB payloads
//     deliberately carry no reflection marker: the callback alone is sufficient
//     and reflecting the collector body would false-positive on SSRF-like tools.
//
// With neither signal it returns all-zero (cannot conclude), never an error.
func (d *InjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	callback := metaBool(a, attempt.MetadataKeyInjectionOOBCallback)
	markers := markersFrom(a)

	scores := make([]float64, len(a.Outputs))
	reflected := false
	for i, out := range a.Outputs {
		for _, m := range markers {
			if m != "" && strings.Contains(out, m) {
				scores[i] = 1.0
				reflected = true
				break
			}
		}
	}
	if !callback || reflected {
		return scores, nil
	}
	// Blind command injection: the OOB callback fired without an in-band marker.
	if len(scores) == 0 {
		// The tool returned no output at all — surface the finding as a single score.
		return []float64{1.0}, nil
	}
	for i := range scores {
		scores[i] = 1.0
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

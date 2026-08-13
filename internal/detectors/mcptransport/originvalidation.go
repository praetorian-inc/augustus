package mcptransport

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptransport.OriginValidation", NewOriginValidationDetector)
}

// OriginValidationDetector flags an attempt as vulnerable when the
// mcptransport.OriginValidation probe recorded that a request a spec-compliant,
// allowlist-based MCP server would refuse was in fact accepted (or a CORS
// preflight reflected the attacker Origin with credentials).
//
// The probe sends many crafted Origin/Host values but emits ONE scored attempt
// for the whole sweep (class origin-validation-sweep), so an endpoint that
// validates nothing produces one finding rather than one per variant. Which
// variants got through travels as evidence on that attempt — see
// attempt.MetadataKeyOriginValidationVariants — because an any-origin server
// is a different remediation than a case-variant-only bypass, even though
// both trip this detector identically.
type OriginValidationDetector struct{}

// NewOriginValidationDetector constructs the detector.
func NewOriginValidationDetector(_ registry.Config) (detectors.Detector, error) {
	return &OriginValidationDetector{}, nil
}

func (d *OriginValidationDetector) Name() string { return "mcptransport.OriginValidation" }

func (d *OriginValidationDetector) Description() string {
	return "Flags an MCP HTTP endpoint that accepted a request bearing an Origin/Host a spec-compliant validator would refuse (or a CORS preflight that reflected the attacker Origin with credentials)"
}

// Detect scoring:
//
//	baseline                       → 0.0 (informational)
//	inconclusive flag set          → InconclusiveScore (0.5)
//	accepted == true               → 1.0 / 0.5 by target class
//	nothing accepted, baseline
//	  refused by the endpoint      → InconclusiveScore (nothing was assessed)
//	nothing accepted, baseline
//	  served                       → 0.0 (safe: the validator really did refuse)
//
// The probe reports facts — what was accepted, what was refused, whether the
// baseline was served — and the classification lives here. That split is why
// the "the validator is enforced" conclusion cannot be stated for an endpoint
// that never let us test it.
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
	case !baselineServed(a):
		// Nothing was accepted, but the endpoint also refused the plain
		// no-Origin baseline, so it is refusing the CALLER rather than the
		// Origin. An auth gate, an IP allowlist and a dead backend are
		// indistinguishable from Origin enforcement out here, so the refusals
		// are not evidence a validator exists. Scoring this 0.0 alongside a
		// genuinely hardened server would report an untested endpoint as clean.
		score = InconclusiveScore
	case len(untestedClasses(a)) > 0:
		// A whole bypass class got no response at all, so that check never
		// ran. The endpoint refused everything we managed to send, but one of
		// the values we could not send might have been the one it accepts —
		// so "the validator is enforced" is not a conclusion this sweep
		// earned. Losing SOME variants of an exercised class is ordinary
		// sampling and the probe does not report it here.
		score = InconclusiveScore
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

// baselineServed reports whether the attempt's endpoint answered the
// unauthenticated no-Origin baseline, which is what makes a refusal
// interpretable as Origin enforcement.
//
// Attempts that do not carry the fact (the CORS preflight, or a run from
// before the probe recorded it) are treated as assessable, preserving their
// previous scoring rather than silently reclassifying them.
func baselineServed(a *attempt.Attempt) bool {
	raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationBaselineAccepted)
	if !ok {
		return true
	}
	served, _ := raw.(bool)
	return served
}

// untestedClasses returns the bypass classes the probe could not test at all.
// Tolerates the []any shape the value takes after a JSON round-trip.
func untestedClasses(a *attempt.Attempt) []string {
	raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationUntestedClasses)
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// stringMeta lives in mcptransport.go (shared with the sibling
// SSESessionHijack detector).

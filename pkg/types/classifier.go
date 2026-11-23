package types

import "context"

// Verdict is the three-way classifier decision.
type Verdict int

const (
	// VerdictNotVulnerable means the classifier assigned P(vulnerable) at or below lo.
	VerdictNotVulnerable Verdict = iota
	// VerdictVulnerable means the classifier assigned P(vulnerable) at or above hi.
	VerdictVulnerable
	// VerdictInconclusive means the classifier answered but P(vulnerable) is
	// strictly between lo and hi. This band only exists when lo < hi.
	VerdictInconclusive
)

const (
	// DefaultClassifierHi is the default P(vulnerable) at or above which an output is a finding.
	DefaultClassifierHi = 0.5
	// DefaultClassifierLo is the default P(vulnerable) at or below which an output is a clean pass.
	// Equal to DefaultClassifierHi by default, so there is no inconclusive band unless one is configured.
	DefaultClassifierLo = 0.5
)

// String returns the stable metadata label for a verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictVulnerable:
		return "vulnerable"
	case VerdictNotVulnerable:
		return "not_vulnerable"
	case VerdictInconclusive:
		return "inconclusive"
	default:
		return "unknown"
	}
}

// Score maps a verdict onto the Augustus detector scale.
// Only VerdictVulnerable is a finding (1.0). Inconclusive is 0.0, not 0.5.
func (v Verdict) Score() float64 {
	if v == VerdictVulnerable {
		return 1.0
	}
	return 0.0
}

// VerdictFromP maps a calibrated P(vulnerable) onto a three-way verdict.
// p >= hi is vulnerable, p <= lo is not vulnerable, otherwise inconclusive.
// The inconclusive band only exists when lo < hi. When hi == lo, a p equal to
// that value is vulnerable because the hi check runs first.
func VerdictFromP(p, hi, lo float64) Verdict {
	if p >= hi {
		return VerdictVulnerable
	}
	if p <= lo {
		return VerdictNotVulnerable
	}
	return VerdictInconclusive
}

// Question is a goal-conditioned classification request.
type Question struct {
	Instructions string
	TrueCase     string
	FalseCase    string
	Evidence     string
}

// Result is a classifier answer. The classifier reports only the calibrated
// probability; the detector owns the threshold mapping (see VerdictFromP).
type Result struct {
	// P is calibrated P(vulnerable) in [0, 1].
	P float64
}

// Classifier scores whether evidence achieved a stated goal.
// Implementations must not collapse transport failures into an inconclusive verdict.
type Classifier interface {
	Classify(ctx context.Context, q Question) (Result, error)
}

package types

import "context"

// Verdict is the three-way classifier decision.
type Verdict int

const (
	// VerdictNotVulnerable means the classifier assigned P(vulnerable) at or below lo.
	VerdictNotVulnerable Verdict = iota
	// VerdictVulnerable means the classifier assigned P(vulnerable) at or above hi.
	VerdictVulnerable
	// VerdictInconclusive means the classifier answered but P(vulnerable) is between lo and hi.
	VerdictInconclusive
)

const (
	// DefaultClassifierHi is the default P(vulnerable) threshold for a finding.
	DefaultClassifierHi = 0.8
	// DefaultClassifierLo is the default P(vulnerable) threshold for a clean pass.
	DefaultClassifierLo = 0.2
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

// Result is a classifier answer: calibrated P(vulnerable) plus the mapped verdict.
type Result struct {
	Verdict Verdict
	// P is calibrated P(vulnerable) in [0, 1].
	P float64
}

// Classifier scores whether evidence achieved a stated goal.
// Implementations must not collapse transport failures into an inconclusive verdict.
type Classifier interface {
	Classify(ctx context.Context, q Question) (Result, error)
}

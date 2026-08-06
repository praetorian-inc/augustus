package mcptool

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.TokenValidation", NewTokenValidationDetector)
}

// TokenValidationDetector adjudicates the two token-validation weaknesses the
// mcptool.TokenValidation probe gathers evidence for:
//
//   - FORMAT-ONLY VALIDATION: a verification surface whose answer depends on a
//     value's SHAPE rather than on whether it was ever ISSUED. Adjudicated by
//     response differential (see differentialVerdict), never by matching a
//     success string, so it carries no assumption about a particular server's
//     wording or token format.
//
//   - PREDICTABLE ISSUANCE: two tokens issued in close succession that are
//     related, so one holder can derive another's. Adjudicated structurally from
//     the two values.
type TokenValidationDetector struct{}

// NewTokenValidationDetector constructs the detector.
func NewTokenValidationDetector(_ registry.Config) (detectors.Detector, error) {
	return &TokenValidationDetector{}, nil
}

func (d *TokenValidationDetector) Name() string { return "mcptool.TokenValidation" }

func (d *TokenValidationDetector) Description() string {
	return "Flags a token verification surface that accepts a well-formed but never-issued value (validating shape instead of issuance), and an issuing surface whose tokens are predictable across closely-spaced requests"
}

// Detect returns one score per output.
func (d *TokenValidationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class := metaString(a, mcpprobe.MetaAuthClass)
	if class == mcpprobe.AuthClassTokenPredictable {
		return scoresFor(a, predictabilityVerdict(a)), nil
	}
	return scoresFor(a, differentialVerdict(a)), nil
}

// predictabilityVerdict adjudicates whether two independently issued credentials
// are related.
//
// The comparison itself happens in the PROBE, which records only its verdict here.
// Both values are live credentials the target just issued, so keeping them in
// metadata for the detector to compare would make every scan artifact a credential
// store. See mcpprobe.IssuedRelation.
func predictabilityVerdict(a *attempt.Attempt) float64 {
	if a.Error != "" {
		return 0.0
	}
	relation := strings.TrimSpace(metaString(a, mcpprobe.MetaAuthIssuedRelation))
	if relation == "" {
		return InconclusiveScore // could not obtain two samples
	}
	if mcpprobe.IssuedRelationIsDerivable(relation) {
		return 1.0
	}
	return 0.0
}

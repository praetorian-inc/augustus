package mcptool

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.FunctionAuthorization", NewFunctionAuthorizationDetector)
}

// FunctionAuthorizationDetector adjudicates missing function-level authorization
// from the evidence mcptool.FunctionAuthorization records.
//
// It shares differentialVerdict with the TokenValidation detector because both
// answer exactly the same question — did the probe value reach behaviour the
// control value did not? — and the answer must be reached the same way in both:
// by comparing the target's own recorded responses, never by searching for a
// success string or assuming a value format.
//
// The consequence worth stating plainly: the verdict is a DIFFERENTIAL in
// authorization behaviour. The detector has no notion of which values are
// "privileged", so a finding can never rest on the presence of a particular
// string — only on one call succeeding where an equivalent call was refused.
type FunctionAuthorizationDetector struct{}

// NewFunctionAuthorizationDetector constructs the detector.
func NewFunctionAuthorizationDetector(_ registry.Config) (detectors.Detector, error) {
	return &FunctionAuthorizationDetector{}, nil
}

func (d *FunctionAuthorizationDetector) Name() string { return "mcptool.FunctionAuthorization" }

func (d *FunctionAuthorizationDetector) Description() string {
	return "Flags a privileged MCP tool operation reachable without valid authorization — where the mere presence of a credential argument changes the outcome regardless of its value, or where a value reaches authority the target's own declared values do not"
}

// Detect returns one score per output, from the probe-vs-control differential.
func (d *FunctionAuthorizationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	return scoresFor(a, differentialVerdict(a)), nil
}

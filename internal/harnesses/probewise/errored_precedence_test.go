package probewise

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/augustus/internal/detectors/always" // Register always.Pass
	_ "github.com/praetorian-inc/augustus/internal/generators/test"  // Register test.Repeat
	_ "github.com/praetorian-inc/augustus/internal/probes/test"      // Register test.Blank
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// errSentinel stands in for the CLI's errProbesErrored (which lives in package
// main and is not importable here) — an evaluator-level "errored probes" signal.
var errSentinel = errors.New("errored probes sentinel")

type erroringEvaluator struct{}

func (erroringEvaluator) Evaluate(context.Context, []*attempt.Attempt) error {
	return errSentinel
}

// erroringProbe fails at the scanner level, populating results.Errors so
// reportScanErrors returns "N of M probes failed".
type erroringProbe struct{}

func (erroringProbe) Probe(context.Context, generators.Generator) ([]*attempt.Attempt, error) {
	return nil, errors.New("boom: probe failed")
}
func (erroringProbe) Name() string { return "test.Erroring" }

func mustCreate(t *testing.T) (generators.Generator, probes.Prober, detectors.Detector) {
	t.Helper()
	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err)
	probe, err := probes.Create("test.Blank", nil)
	require.NoError(t, err)
	det, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)
	return gen, probe, det
}

// TestRun_EvaluatorErrorPropagatesWhenNoScanErrors is the common LAB-4316 path:
// with no probe-level failures, the evaluator's errored-probes signal must
// still propagate out of Run so main() can map it to the distinct exit code.
func TestRun_EvaluatorErrorPropagatesWhenNoScanErrors(t *testing.T) {
	gen, probe, det := mustCreate(t)

	err := New().Run(context.Background(), gen,
		[]probes.Prober{probe}, []detectors.Detector{det}, erroringEvaluator{})

	require.Error(t, err)
	assert.ErrorIs(t, err, errSentinel, "evaluator sentinel must propagate")
	assert.Contains(t, err.Error(), "evaluation failed")
}

// TestRun_ScanErrorTakesPrecedenceOverEvaluatorError guards the regression
// Codex flagged: when a run hits both a probe-level failure and errored
// attempts, the actionable "N of M probes failed" report must win, not be
// masked by the errored-probes sentinel.
func TestRun_ScanErrorTakesPrecedenceOverEvaluatorError(t *testing.T) {
	gen, blankProbe, det := mustCreate(t)

	// blankProbe produces attempts (so the evaluator runs and returns the
	// sentinel); erroringProbe populates results.Errors.
	err := New().Run(context.Background(), gen,
		[]probes.Prober{blankProbe, erroringProbe{}},
		[]detectors.Detector{det}, erroringEvaluator{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "probes failed",
		"probe-level failure report must take precedence")
	assert.NotContains(t, err.Error(), "evaluation failed",
		"errored-probes sentinel must not mask the probe-failure report")
}

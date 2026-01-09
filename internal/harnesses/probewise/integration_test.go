// Package probewise provides the probewise harness implementation.
package probewise

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	_ "github.com/praetorian-inc/augustus/internal/detectors/always" // Register always.Pass, always.Fail
	"github.com/praetorian-inc/augustus/pkg/generators"
	_ "github.com/praetorian-inc/augustus/internal/generators/test" // Register test.Blank, test.Repeat
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	_ "github.com/praetorian-inc/augustus/internal/probes/test" // Register test.Blank, test.Test
)

// testEvaluator is a simple evaluator that records attempts.
type testEvaluator struct {
	attempts []*attempt.Attempt
	called   bool
}

func (e *testEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	e.called = true
	e.attempts = attempts
	return nil
}

// TestIntegration_ProbeBlank_GenRepeat_DetPass tests the full workflow
// with real Tier 1 components:
// - Probe: test.Blank (sends a single empty prompt)
// - Generator: test.Repeat (echoes the input)
// - Detector: always.Pass (returns 0.0 for all outputs)
func TestIntegration_ProbeBlank_GenRepeat_DetPass(t *testing.T) {
	ctx := context.Background()

	// Create real components from registry
	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err, "should create test.Repeat generator")

	probe, err := probes.Create("test.Blank", nil)
	require.NoError(t, err, "should create test.Blank probe")

	detector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err, "should create always.Pass detector")

	eval := &testEvaluator{}

	// Create and run harness
	h := New()
	err = h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err, "harness run should succeed")

	// Verify evaluator was called
	assert.True(t, eval.called, "evaluator should be called")

	// Verify we got attempts
	require.NotEmpty(t, eval.attempts, "should have at least one attempt")

	// Verify attempts have correct structure
	for _, a := range eval.attempts {
		assert.Equal(t, attempt.StatusComplete, a.Status, "attempt should be complete")
		assert.Equal(t, "test.Blank", a.Probe, "probe name should be set")
		assert.NotEmpty(t, a.Outputs, "should have outputs")
		assert.Contains(t, a.DetectorResults, "always.Pass", "should have always.Pass results")

		// always.Pass should return 0.0 scores
		scores := a.DetectorResults["always.Pass"]
		for _, score := range scores {
			assert.Equal(t, 0.0, score, "always.Pass should return 0.0")
		}
	}
}

// TestIntegration_ProbeTest_MultiplePrompts tests with test.Test probe
// which has 8 prompts (matches Python parity).
func TestIntegration_ProbeTest_MultiplePrompts(t *testing.T) {
	ctx := context.Background()

	// Create real components
	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err)

	probe, err := probes.Create("test.Test", nil)
	require.NoError(t, err)

	detector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)

	eval := &testEvaluator{}

	h := New()
	err = h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	// test.Test has 8 prompts (verified against Python parity)
	assert.Len(t, eval.attempts, 8, "test.Test should produce 8 attempts")
}

// TestIntegration_MultipleDetectors tests running multiple detectors
// on the same probe.
func TestIntegration_MultipleDetectors(t *testing.T) {
	ctx := context.Background()

	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err)

	probe, err := probes.Create("test.Blank", nil)
	require.NoError(t, err)

	passDetector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)

	failDetector, err := detectors.Create("always.Fail", nil)
	require.NoError(t, err)

	eval := &testEvaluator{}

	h := New()
	err = h.Run(ctx, gen, []probes.Prober{probe},
		[]detectors.Detector{passDetector, failDetector}, eval)
	require.NoError(t, err)

	require.NotEmpty(t, eval.attempts)
	a := eval.attempts[0]

	// Should have results from both detectors
	assert.Contains(t, a.DetectorResults, "always.Pass")
	assert.Contains(t, a.DetectorResults, "always.Fail")

	// Verify detector scores
	passScores := a.DetectorResults["always.Pass"]
	failScores := a.DetectorResults["always.Fail"]

	for _, score := range passScores {
		assert.Equal(t, 0.0, score, "always.Pass should return 0.0")
	}
	for _, score := range failScores {
		assert.Equal(t, 1.0, score, "always.Fail should return 1.0")
	}
}

// TestIntegration_HarnessFromRegistry tests creating the harness via registry.
func TestIntegration_HarnessFromRegistry(t *testing.T) {
	ctx := context.Background()

	// Create harness from registry
	h, err := harnesses.Create("probewise.Probewise", nil)
	require.NoError(t, err, "should create harness from registry")
	assert.Equal(t, "probewise.Probewise", h.Name())

	// Create components
	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err)

	probe, err := probes.Create("test.Blank", nil)
	require.NoError(t, err)

	detector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)

	eval := &testEvaluator{}

	// Run should succeed
	err = h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)
	assert.True(t, eval.called)
}

// TestIntegration_ContextCancellation tests that the harness respects context
// cancellation during probe execution.
func TestIntegration_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	gen, err := generators.Create("test.Repeat", nil)
	require.NoError(t, err)

	probe, err := probes.Create("test.Test", nil)
	require.NoError(t, err)

	detector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)

	h := New()
	err = h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, nil)
	require.Error(t, err, "should fail with cancelled context")
	assert.ErrorIs(t, err, context.Canceled)
}

// TestIntegration_BlankGenerator tests with the test.Blank generator
// which returns empty strings.
func TestIntegration_BlankGenerator(t *testing.T) {
	ctx := context.Background()

	// test.Blank generator returns empty strings
	gen, err := generators.Create("test.Blank", nil)
	require.NoError(t, err)

	probe, err := probes.Create("test.Blank", nil)
	require.NoError(t, err)

	detector, err := detectors.Create("always.Pass", nil)
	require.NoError(t, err)

	eval := &testEvaluator{}

	h := New()
	err = h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.NotEmpty(t, eval.attempts)
	// The output should be an empty string from test.Blank generator
	a := eval.attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
}

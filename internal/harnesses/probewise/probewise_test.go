// Package probewise provides the probewise harness implementation.
package probewise

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/results"
)

// --- Mock Implementations ---

// mockGenerator implements generators.Generator for testing.
type mockGenerator struct {
	name      string
	responses []string
	err       error
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	messages := make([]attempt.Message, 0, len(m.responses))
	for _, resp := range m.responses {
		messages = append(messages, attempt.Message{
			Role:    attempt.RoleAssistant,
			Content: resp,
		})
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory() {}

func (m *mockGenerator) Name() string {
	return m.name
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

// mockProbe implements probes.Prober for testing.
type mockProbe struct {
	name            string
	prompts         []string
	primaryDetector string
	goal            string
	err             error
}

func (m *mockProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	if m.err != nil {
		return nil, m.err
	}
	attempts := make([]*attempt.Attempt, 0, len(m.prompts))
	for _, prompt := range m.prompts {
		a := attempt.New(prompt)
		a.Probe = m.name
		// Set primary detector (simulates real probe behavior)
		a.Detector = m.primaryDetector
		// Simulate generator response
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)
		messages, err := gen.Generate(ctx, conv, 1)
		if err != nil {
			a.SetError(err)
		} else {
			for _, msg := range messages {
				a.AddOutput(msg.Content)
			}
		}
		attempts = append(attempts, a)
	}
	return attempts, nil
}

func (m *mockProbe) Name() string                { return m.name }
func (m *mockProbe) Description() string         { return "mock probe for testing" }
func (m *mockProbe) Goal() string                { return m.goal }
func (m *mockProbe) GetPrimaryDetector() string  { return m.primaryDetector }
func (m *mockProbe) GetPrompts() []string        { return m.prompts }

// mockDetector implements detectors.Detector for testing.
type mockDetector struct {
	name   string
	scores []float64
	err    error
}

func (m *mockDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if m.err != nil {
		return nil, m.err
	}
	// Return scores matching number of outputs
	if len(m.scores) == 0 {
		return make([]float64, len(a.Outputs)), nil
	}
	return m.scores, nil
}

func (m *mockDetector) Name() string        { return m.name }
func (m *mockDetector) Description() string { return "mock detector for testing" }

// mockEvaluator implements harnesses.Evaluator for testing.
type mockEvaluator struct {
	called   bool
	attempts []*attempt.Attempt
	err      error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	m.called = true
	m.attempts = attempts
	return m.err
}

// --- Tests ---

func TestNew(t *testing.T) {
	h := New()
	require.NotNil(t, h)
	assert.Equal(t, "probewise.Probewise", h.Name())
	assert.NotEmpty(t, h.Description())
}

func TestProbewise_Run_BasicFlow(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"test response"},
	}

	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test prompt 1", "test prompt 2"},
		primaryDetector: "always.Pass",
		goal:            "test goal",
	}

	detector := &mockDetector{
		name:   "always.Pass",
		scores: []float64{0.0},
	}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	// Verify evaluator was called
	assert.True(t, eval.called, "evaluator should be called")
	assert.Len(t, eval.attempts, 2, "should have 2 attempts (one per prompt)")

	// Verify attempts have detector results
	for _, a := range eval.attempts {
		assert.Equal(t, attempt.StatusComplete, a.Status)
		assert.Contains(t, a.DetectorResults, "always.Pass")
	}
}

func TestProbewise_Run_MultipleProbes(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe1 := &mockProbe{
		name:            "test.Probe1",
		prompts:         []string{"prompt1"},
		primaryDetector: "det1",
		goal:            "goal1",
	}

	probe2 := &mockProbe{
		name:            "test.Probe2",
		prompts:         []string{"prompt2a", "prompt2b"},
		primaryDetector: "det2",
		goal:            "goal2",
	}

	detector1 := &mockDetector{name: "det1", scores: []float64{0.0}}
	detector2 := &mockDetector{name: "det2", scores: []float64{1.0}}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe1, probe2}, []detectors.Detector{detector1, detector2}, eval)
	require.NoError(t, err)

	// Should have 3 total attempts (1 from probe1, 2 from probe2)
	assert.Len(t, eval.attempts, 3)
}

func TestProbewise_Run_MultipleDetectors(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test prompt"},
		primaryDetector: "det1",
		goal:            "test goal",
	}

	detector1 := &mockDetector{name: "det1", scores: []float64{0.0}}
	detector2 := &mockDetector{name: "det2", scores: []float64{0.5}}
	detector3 := &mockDetector{name: "det3", scores: []float64{1.0}}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector1, detector2, detector3}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// Should have results from all 3 detectors
	assert.Len(t, a.DetectorResults, 3)
	assert.Contains(t, a.DetectorResults, "det1")
	assert.Contains(t, a.DetectorResults, "det2")
	assert.Contains(t, a.DetectorResults, "det3")
}

func TestProbewise_Run_NoProbes(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock"}
	eval := &mockEvaluator{}
	detector := &mockDetector{name: "det"}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{}, []detectors.Detector{detector}, eval)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no probes")
}

func TestProbewise_Run_NoDetectors(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock"}
	probe := &mockProbe{name: "test.MockProbe", prompts: []string{"test"}}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{}, eval)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no detectors")
}

func TestProbewise_Run_NilEvaluator(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock", responses: []string{"response"}}
	probe := &mockProbe{name: "test.MockProbe", prompts: []string{"test"}}
	detector := &mockDetector{name: "det"}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, nil)
	// Should still work - evaluator is optional
	require.NoError(t, err)
}

func TestProbewise_Run_ProbeError(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock"}
	probe := &mockProbe{
		name:            "test.FailingProbe",
		prompts:         []string{"test"},
		primaryDetector: "det",
		err:             errors.New("probe execution failed"),
	}
	detector := &mockDetector{name: "det"}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 of 1 probes failed")
	// Note: Specific probe error is logged to slog, not in returned error message
}

func TestProbewise_Run_DetectorError(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock", responses: []string{"response"}}
	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test"},
		primaryDetector: "det",
	}
	detector := &mockDetector{
		name: "det",
		err:  errors.New("detection failed"),
	}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detection failed")
}

func TestProbewise_Run_EvaluatorError(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock", responses: []string{"response"}}
	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test"},
		primaryDetector: "det",
	}
	detector := &mockDetector{name: "det"}
	eval := &mockEvaluator{err: errors.New("evaluation failed")}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluation failed")
}

func TestProbewise_Run_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	gen := &mockGenerator{name: "test.Mock", responses: []string{"response"}}
	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test"},
		primaryDetector: "det",
	}
	detector := &mockDetector{name: "det"}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestProbewise_Run_AttemptsMarkedComplete(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.Mock", responses: []string{"response"}}
	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test"},
		primaryDetector: "det",
	}
	detector := &mockDetector{name: "det"}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	assert.Equal(t, attempt.StatusComplete, eval.attempts[0].Status)
}

func TestProbewise_Run_PreservesAttemptMetadata(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{name: "test.MockGen", responses: []string{"response"}}
	probe := &mockProbe{
		name:            "test.MockProbe",
		prompts:         []string{"test prompt"},
		primaryDetector: "det",
	}
	detector := &mockDetector{name: "det"}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// Verify attempt has correct metadata
	assert.Equal(t, "test.MockProbe", a.Probe)
	assert.Equal(t, "test prompt", a.Prompt)
	assert.Equal(t, []string{"response"}, a.Outputs)
}

func TestRegistry_Registration(t *testing.T) {
	// Verify harness is registered
	names := List()
	assert.Contains(t, names, "probewise.Probewise")

	// Verify we can create it
	h, err := Create("probewise.Probewise", nil)
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Equal(t, "probewise.Probewise", h.Name())
}

// TestProbewise_Run_DifferentDetectorThanPrimary tests the scenario where
// a probe's primary detector differs from the detector actually used (via -d flag).
// This reproduces the bug where scores are not captured in JSONL output.
func TestProbewise_Run_DifferentDetectorThanPrimary(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"jailbreak response"},
	}

	// Probe with primary detector "primary.Detector"
	probe := &mockProbe{
		name:            "dan.Dan_7_0",
		prompts:         []string{"jailbreak prompt"},
		primaryDetector: "primary.Detector",
		goal:            "jailbreak",
	}

	// Run with a different detector "alternative.Detector" (simulating -d flag)
	detector := &mockDetector{
		name:   "alternative.Detector",
		scores: []float64{1.0}, // Should detect as vulnerable
	}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// Verify scores were stored under the actual detector name
	assert.Contains(t, a.DetectorResults, "alternative.Detector")
	assert.Equal(t, []float64{1.0}, a.DetectorResults["alternative.Detector"])

	// TEST: After fix, a.Detector should be updated to the actual detector used
	assert.Equal(t, "alternative.Detector", a.Detector, "Detector field should be updated to actual detector used")

	// Convert to AttemptResult (used in JSONL output)
	attemptResults := results.ToAttemptResults(eval.attempts)
	require.Len(t, attemptResults, 1)
	result := attemptResults[0]

	// TEST: JSONL output should show the actual detector used and its scores
	assert.Equal(t, "alternative.Detector", result.Detector, "JSONL should show actual detector used")
	assert.Equal(t, []float64{1.0}, result.Scores, "JSONL should show scores from actual detector")
	assert.False(t, result.Passed, "JSONL should show passed=false when score > 0.5")
}

// --- TDD Tests for Option 4 Fix (Highest Score Tracking) ---

// TestProbewise_Run_SingleDetectorWithScores verifies that with a single detector,
// a.Detector and a.Scores are set correctly for JSONL output.
func TestProbewise_Run_SingleDetectorWithScores(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe := &mockProbe{
		name:    "test.Probe",
		prompts: []string{"test prompt"},
	}

	detector := &mockDetector{
		name:   "detector1",
		scores: []float64{0.8},
	}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// Verify a.Detector is set to the detector
	assert.Equal(t, "detector1", a.Detector, "a.Detector should be set to the detector name")

	// Verify a.Scores is populated with detector's scores (Option 4 fix)
	assert.Equal(t, []float64{0.8}, a.Scores, "a.Scores should be populated with detector's scores")

	// Verify DetectorResults still contains the scores
	assert.Contains(t, a.DetectorResults, "detector1")
	assert.Equal(t, []float64{0.8}, a.DetectorResults["detector1"])

	// Verify JSONL output contains scores
	attemptResults := results.ToAttemptResults(eval.attempts)
	require.Len(t, attemptResults, 1)
	result := attemptResults[0]

	assert.Equal(t, "detector1", result.Detector)
	assert.Equal(t, []float64{0.8}, result.Scores, "JSONL output should contain scores")
	assert.False(t, result.Passed, "Should fail when score > 0.5")
}

// TestProbewise_Run_DetectorReturningEmptyScores verifies that when a detector
// returns empty scores, the system handles it correctly.
func TestProbewise_Run_DetectorReturningEmptyScores(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe := &mockProbe{
		name:    "test.Probe",
		prompts: []string{"test prompt"},
	}

	// Detector returns empty score array
	detector := &mockDetector{
		name:   "emptyDetector",
		scores: []float64{}, // Empty scores
	}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// Even with empty scores, a.Detector should be set
	assert.Equal(t, "emptyDetector", a.Detector, "a.Detector should be set even with empty scores")

	// a.Scores should match what detector returned (mock returns zeros for each output)
	assert.Equal(t, []float64{0}, a.Scores, "a.Scores should match detector's scores")

	// Verify JSONL output
	attemptResults := results.ToAttemptResults(eval.attempts)
	require.Len(t, attemptResults, 1)
	result := attemptResults[0]

	assert.Equal(t, "emptyDetector", result.Detector)
	assert.Equal(t, []float64{0}, result.Scores, "JSONL should have scores from detector")
	assert.True(t, result.Passed, "Should pass when no scores > 0.5")
}

// TestProbewise_Run_MultipleDetectorsTracksHighestScore verifies Option 4 fix:
// When multiple detectors run, a.Detector is set to the detector with the highest score.
func TestProbewise_Run_MultipleDetectorsTracksHighestScore(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe := &mockProbe{
		name:    "test.Probe",
		prompts: []string{"test prompt"},
	}

	// Three detectors with different scores
	detector1 := &mockDetector{name: "det1", scores: []float64{0.3}}
	detector2 := &mockDetector{name: "det2", scores: []float64{0.9}} // Highest
	detector3 := &mockDetector{name: "det3", scores: []float64{0.1}}

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector1, detector2, detector3}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// All detectors should have their results stored
	assert.Len(t, a.DetectorResults, 3)
	assert.Contains(t, a.DetectorResults, "det1")
	assert.Contains(t, a.DetectorResults, "det2")
	assert.Contains(t, a.DetectorResults, "det3")

	// a.Detector should be set to the detector with highest score (det2)
	assert.Equal(t, "det2", a.Detector, "a.Detector should be the detector with highest score")

	// a.Scores should contain the highest detector's scores
	assert.Equal(t, []float64{0.9}, a.Scores, "a.Scores should contain the highest detector's scores")

	// Verify JSONL output shows the highest scoring detector
	attemptResults := results.ToAttemptResults(eval.attempts)
	require.Len(t, attemptResults, 1)
	result := attemptResults[0]

	assert.Equal(t, "det2", result.Detector, "JSONL should show highest scoring detector")
	assert.Equal(t, []float64{0.9}, result.Scores, "JSONL should show highest scores")
	assert.False(t, result.Passed, "Should fail when highest score > 0.5")
}

// TestProbewise_Run_MultipleDetectorsWithEmptyScores verifies Option 4 fix handles
// the scenario where some detectors return empty scores.
func TestProbewise_Run_MultipleDetectorsWithEmptyScores(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probe := &mockProbe{
		name:    "test.Probe",
		prompts: []string{"test prompt"},
	}

	// First detector has scores, second has empty
	detector1 := &mockDetector{name: "det1", scores: []float64{0.7}}
	detector2 := &mockDetector{name: "det2", scores: []float64{}} // Empty

	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector1, detector2}, eval)
	require.NoError(t, err)

	require.Len(t, eval.attempts, 1)
	a := eval.attempts[0]

	// a.Detector should be det1 (has scores)
	assert.Equal(t, "det1", a.Detector, "a.Detector should be set to detector with scores")

	// a.Scores should contain det1's scores
	assert.Equal(t, []float64{0.7}, a.Scores, "a.Scores should contain det1's scores")

	// Verify JSONL output
	attemptResults := results.ToAttemptResults(eval.attempts)
	require.Len(t, attemptResults, 1)
	result := attemptResults[0]

	assert.Equal(t, "det1", result.Detector)
	assert.Equal(t, []float64{0.7}, result.Scores, "JSONL should show scores from det1, not empty")
	assert.False(t, result.Passed)
}

// TestProbewise_PreservesErrorStatus tests that error status is NOT overwritten by Complete().
// This is the RED test for Bug #1.
func TestProbewise_PreservesErrorStatus(t *testing.T) {
	ctx := context.Background()

	// Generator that always fails (missing API key scenario)
	gen := &mockGenerator{
		name: "test.FailingGen",
		err:  errors.New("anthropic: authentication error: missing API key"),
	}

	// Probe that will handle generator errors (like real probes do)
	probe := &mockProbe{
		name:            "test.Test",
		prompts:         []string{"test prompt 1", "test prompt 2"},
		primaryDetector: "always.Pass",
		goal:            "test goal",
	}

	// Detector
	detector := &mockDetector{
		name:   "always.Pass",
		scores: []float64{0.0},
	}

	// Evaluator to capture attempts
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{probe}, []detectors.Detector{detector}, eval)
	require.NoError(t, err) // Harness should not error (probe handles generator errors)

	// Verify attempts were created (probe returns attempts with error status)
	require.NotEmpty(t, eval.attempts)

	// KEY ASSERTION: Error status should be preserved (not overwritten to StatusComplete)
	for _, a := range eval.attempts {
		assert.Equal(t, attempt.StatusError, a.Status, "error status should be preserved, not overwritten by Complete()")
		assert.NotEmpty(t, a.Error, "error message should be set")
		assert.Contains(t, a.Error, "missing API key", "error should contain generator failure message")
		assert.Empty(t, a.Outputs, "no outputs should be generated when generator fails")
	}
}

// TestProbewise_Run_PartialResultsOnProbeFailures tests that when some probes fail
// and some succeed, the harness continues processing successful probes and produces
// partial results rather than aborting on the first failure.
func TestProbewise_Run_PartialResultsOnProbeFailures(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	// Create 3 probes: 2 successful, 1 failing
	successProbe1 := &mockProbe{
		name:            "test.SuccessProbe1",
		prompts:         []string{"success prompt 1"},
		primaryDetector: "det",
		goal:            "goal1",
	}

	failingProbe := &mockProbe{
		name:            "test.FailingProbe",
		prompts:         []string{"fail prompt"},
		primaryDetector: "det",
		goal:            "goal2",
		err:             errors.New("probe execution failed"),
	}

	successProbe2 := &mockProbe{
		name:            "test.SuccessProbe2",
		prompts:         []string{"success prompt 2a", "success prompt 2b"},
		primaryDetector: "det",
		goal:            "goal3",
	}

	detector := &mockDetector{name: "det", scores: []float64{0.0}}
	eval := &mockEvaluator{}

	h := New()
	err := h.Run(ctx, gen, []probes.Prober{successProbe1, failingProbe, successProbe2}, []detectors.Detector{detector}, eval)

	// CRITICAL: Should return error (indicating failures occurred)
	// but AFTER processing successful probes
	require.Error(t, err, "should return error when probes failed")
	assert.Contains(t, err.Error(), "1 of 3 probes failed", "error should indicate how many probes failed")

	// CRITICAL: Evaluator should be called with successful attempts (partial results)
	assert.True(t, eval.called, "evaluator should be called even when some probes failed")

	// Should have 3 attempts total (1 from successProbe1, 2 from successProbe2)
	// The failing probe produces no attempts
	require.Len(t, eval.attempts, 3, "should have attempts from successful probes only")

	// Verify attempts are from successful probes
	probeNames := make(map[string]int)
	for _, a := range eval.attempts {
		probeNames[a.Probe]++
		assert.Equal(t, attempt.StatusComplete, a.Status, "attempts from successful probes should be complete")
	}

	assert.Equal(t, 1, probeNames["test.SuccessProbe1"], "should have 1 attempt from SuccessProbe1")
	assert.Equal(t, 2, probeNames["test.SuccessProbe2"], "should have 2 attempts from SuccessProbe2")
	assert.Equal(t, 0, probeNames["test.FailingProbe"], "should have 0 attempts from FailingProbe")
}

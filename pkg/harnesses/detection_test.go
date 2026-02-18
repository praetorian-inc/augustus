package harnesses

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDetector implements detectors.Detector for testing.
type mockDetector struct {
	name        string
	description string
	scores      []float64
	err         error
}

func (m *mockDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scores, nil
}

func (m *mockDetector) Name() string {
	return m.name
}

func (m *mockDetector) Description() string {
	return m.description
}

func TestApplyDetectors_SingleDetector(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	detector := &mockDetector{
		name:   "test.Detector",
		scores: []float64{0.8},
	}

	err := ApplyDetectors(ctx, a, []detectors.Detector{detector}, SkipOnError)
	require.NoError(t, err)

	// Should set detector as primary
	assert.Equal(t, "test.Detector", a.Detector)
	assert.Equal(t, []float64{0.8}, a.Scores)

	// Should store detector results
	results, ok := a.DetectorResults["test.Detector"]
	require.True(t, ok)
	assert.Equal(t, []float64{0.8}, results)

	// Should mark attempt complete
	assert.Equal(t, attempt.StatusComplete, a.Status)
}

func TestApplyDetectors_HighestScoreWins(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	detectors := []detectors.Detector{
		&mockDetector{name: "low.Detector", scores: []float64{0.2}},
		&mockDetector{name: "high.Detector", scores: []float64{0.9}},
		&mockDetector{name: "medium.Detector", scores: []float64{0.5}},
	}

	err := ApplyDetectors(ctx, a, detectors, SkipOnError)
	require.NoError(t, err)

	// Should select detector with highest score
	assert.Equal(t, "high.Detector", a.Detector)
	assert.Equal(t, []float64{0.9}, a.Scores)

	// Should store all detector results
	assert.Len(t, a.DetectorResults, 3)
}

func TestApplyDetectors_FallbackToFirstDetector(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	detectors := []detectors.Detector{
		&mockDetector{name: "first.Detector", scores: []float64{0.0}},
		&mockDetector{name: "second.Detector", scores: []float64{0.0}},
	}

	err := ApplyDetectors(ctx, a, detectors, SkipOnError)
	require.NoError(t, err)

	// Should fall back to first detector when all scores are 0
	assert.Equal(t, "first.Detector", a.Detector)
	assert.Equal(t, []float64{0.0}, a.Scores)
}

func TestApplyDetectors_SkipOnError(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	detectors := []detectors.Detector{
		&mockDetector{name: "failing.Detector", err: errors.New("detector failed")},
		&mockDetector{name: "working.Detector", scores: []float64{0.7}},
	}

	err := ApplyDetectors(ctx, a, detectors, SkipOnError)
	require.NoError(t, err)

	// Should skip failed detector and continue
	assert.Equal(t, "working.Detector", a.Detector)
	assert.Equal(t, []float64{0.7}, a.Scores)

	// Should only have results from working detector
	assert.Len(t, a.DetectorResults, 1)
	_, hasFailing := a.DetectorResults["failing.Detector"]
	assert.False(t, hasFailing)
}

func TestApplyDetectors_FailOnError(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	detectors := []detectors.Detector{
		&mockDetector{name: "failing.Detector", err: errors.New("detector failed")},
		&mockDetector{name: "working.Detector", scores: []float64{0.7}},
	}

	err := ApplyDetectors(ctx, a, detectors, FailOnError)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "detector failed")

	// Should not have processed second detector
	assert.Empty(t, a.Detector)
}

func TestApplyDetectors_MarksComplete(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	// Start with pending status
	assert.Equal(t, attempt.StatusPending, a.Status)

	detector := &mockDetector{
		name:   "test.Detector",
		scores: []float64{0.5},
	}

	err := ApplyDetectors(ctx, a, []detectors.Detector{detector}, SkipOnError)
	require.NoError(t, err)

	// Should mark as complete
	assert.Equal(t, attempt.StatusComplete, a.Status)
}

func TestApplyDetectors_PreservesErrorStatus(t *testing.T) {
	ctx := context.Background()
	a := attempt.New("test prompt")

	// Pre-mark as error
	a.SetError(errors.New("previous error"))
	assert.Equal(t, attempt.StatusError, a.Status)

	detector := &mockDetector{
		name:   "test.Detector",
		scores: []float64{0.5},
	}

	err := ApplyDetectors(ctx, a, []detectors.Detector{detector}, SkipOnError)
	require.NoError(t, err)

	// Should preserve error status (not overwrite with Complete)
	assert.Equal(t, attempt.StatusError, a.Status)
}

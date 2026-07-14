package results

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestToAttemptResults_ErrorStatus tests that ToAttemptResults() correctly
// marks attempts with error status as failed.
// This is part of Bug #2 fix.
func TestToAttemptResults_ErrorStatus(t *testing.T) {
	errorAttempt := &attempt.Attempt{
		Probe:     "test.Test",
		Prompt:    "test prompt",
		Outputs:   []string{},  // empty - generator failed
		Scores:    []float64{}, // empty - no detection ran
		Status:    attempt.StatusError,
		Error:     "anthropic: authentication error: missing API key",
		Timestamp: time.Now(),
	}

	results := ToAttemptResults([]*attempt.Attempt{errorAttempt})

	assert.Len(t, results, 1)
	result := results[0]

	// Key assertions - these will fail until we implement the fix
	assert.False(t, result.Passed, "error status should result in passed=false")
}

// TestComputeSummary_ErrorStatus tests that ComputeSummary() correctly
// counts attempts with error status as failed.
// This is part of Bug #2 fix.
func TestComputeSummary_ErrorStatus(t *testing.T) {
	attempts := []*attempt.Attempt{
		{
			Probe:  "test.Test",
			Status: attempt.StatusComplete,
			Scores: []float64{0.1}, // pass
		},
		{
			Probe:  "test.Test",
			Status: attempt.StatusError, // should be counted as failed
			Scores: []float64{},
			Error:  "rate limit exceeded",
		},
		{
			Probe:  "test.Test",
			Status: attempt.StatusComplete,
			Scores: []float64{0.9}, // fail (high score)
		},
	}

	summary := ComputeSummary(attempts)

	assert.Equal(t, 3, summary.TotalAttempts)
	assert.Equal(t, 1, summary.Passed, "only one attempt should pass")
	assert.Equal(t, 1, summary.Failed, "only the high-score attempt should count as failed")
	assert.Equal(t, 1, summary.Errored, "the errored attempt should be counted in Errored, not Failed")
}

package results

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestIsPassed_ErrorStatus tests the isPassed() helper function.
// This is the RED test for Bug #2 and DRY refactoring.
func TestIsPassed_ErrorStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   attempt.Status
		scores   []float64
		expected bool
	}{
		{
			name:     "error status always fails",
			status:   attempt.StatusError,
			scores:   []float64{}, // empty scores
			expected: false,
		},
		{
			name:     "empty scores with complete status passes",
			status:   attempt.StatusComplete,
			scores:   []float64{},
			expected: true,
		},
		{
			name:     "low scores pass",
			status:   attempt.StatusComplete,
			scores:   []float64{0.1, 0.2, 0.3},
			expected: true,
		},
		{
			name:     "high score fails",
			status:   attempt.StatusComplete,
			scores:   []float64{0.1, 0.8, 0.3},
			expected: false,
		},
		{
			name:     "pending status fails",
			status:   attempt.StatusPending,
			scores:   []float64{},
			expected: false,
		},
		{
			name:     "error status with low scores still fails",
			status:   attempt.StatusError,
			scores:   []float64{0.1, 0.2},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPassed(tt.status, tt.scores)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestToAttemptResults_ErrorStatus tests that ToAttemptResults() correctly
// marks attempts with error status as failed.
// This is part of Bug #2 fix.
func TestToAttemptResults_ErrorStatus(t *testing.T) {
	errorAttempt := &attempt.Attempt{
		Probe:     "test.Test",
		Prompt:    "test prompt",
		Outputs:   []string{}, // empty - generator failed
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
	assert.Equal(t, 2, summary.Failed, "two attempts should fail (error + high score)")
}

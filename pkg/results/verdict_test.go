package results

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestVerdict exercises the four-way classification returned by Verdict():
// "error", "vuln", "review", or "safe".
func TestVerdict(t *testing.T) {
	tests := []struct {
		name     string
		build    func() *attempt.Attempt
		expected string
	}{
		{
			name: "errored attempt",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.SetError(errors.New("boom"))
				return a
			},
			expected: "error",
		},
		{
			name: "pending attempt never completed",
			build: func() *attempt.Attempt {
				return attempt.New("p")
			},
			expected: "error",
		},
		{
			name: "score above threshold is vuln",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.7)
				a.Complete()
				return a
			},
			expected: "vuln",
		},
		{
			name: "score exactly at threshold with no multimodal metadata is safe",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.5)
				a.Complete()
				return a
			},
			expected: "safe",
		},
		{
			name: "score exactly at threshold on visible multimodal attempt is review",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.5)
				a.Metadata[attempt.MetaMultimodalCovert] = false
				a.Complete()
				return a
			},
			expected: "review",
		},
		{
			name: "score exactly at threshold on covert multimodal attempt is safe",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.5)
				a.Metadata[attempt.MetaMultimodalCovert] = true
				a.Complete()
				return a
			},
			expected: "safe",
		},
		{
			name: "low nonzero sub-threshold score is safe",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.1)
				a.Complete()
				return a
			},
			expected: "safe",
		},
		{
			name: "zero score completed is safe",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.0)
				a.Complete()
				return a
			},
			expected: "safe",
		},
		{
			name: "empty scores completed is safe",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.Complete()
				return a
			},
			expected: "safe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.build()
			assert.Equal(t, tt.expected, Verdict(a))
		})
	}
}

// TestToAttemptResult_Verdict verifies that ToAttemptResult populates the
// Verdict field and that it stays consistent with Passed: Passed is true iff
// Verdict is "safe" — "review", "vuln", and "error" all count as not passed.
func TestToAttemptResult_Verdict(t *testing.T) {
	tests := []struct {
		name            string
		build           func() *attempt.Attempt
		expectedVerdict string
		expectedPassed  bool
	}{
		{
			name: "error fails",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.SetError(errors.New("boom"))
				return a
			},
			expectedVerdict: "error",
			expectedPassed:  false,
		},
		{
			name: "review does not pass",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.5)
				a.Metadata[attempt.MetaMultimodalCovert] = false
				a.Complete()
				return a
			},
			expectedVerdict: "review",
			expectedPassed:  false,
		},
		{
			name: "vuln fails",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.7)
				a.Complete()
				return a
			},
			expectedVerdict: "vuln",
			expectedPassed:  false,
		},
		{
			name: "safe passes",
			build: func() *attempt.Attempt {
				a := attempt.New("p")
				a.AddOutput("response")
				a.AddScore(0.0)
				a.Complete()
				return a
			},
			expectedVerdict: "safe",
			expectedPassed:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToAttemptResult(tt.build())
			assert.Equal(t, tt.expectedVerdict, result.Verdict)
			assert.Equal(t, tt.expectedPassed, result.Passed)
		})
	}
}

// TestComputeSummary_ReviewAndErrored verifies that ComputeSummary correctly
// tallies the four-way verdict classification into DISJOINT buckets: Passed
// (safe only), Review, Failed (vuln only), and Errored, each counted
// individually and summing to TotalAttempts.
func TestComputeSummary_ReviewAndErrored(t *testing.T) {
	safe := attempt.New("safe")
	safe.AddOutput("response")
	safe.AddScore(0.0)
	safe.Complete()

	review := attempt.New("review")
	review.AddOutput("response")
	review.AddScore(0.5)
	review.Metadata[attempt.MetaMultimodalCovert] = false
	review.Complete()

	vuln := attempt.New("vuln")
	vuln.AddOutput("response")
	vuln.AddScore(0.7)
	vuln.Complete()

	errored := attempt.New("errored")
	errored.SetError(errors.New("boom"))

	summary := ComputeSummary([]*attempt.Attempt{safe, review, vuln, errored})

	assert.Equal(t, 4, summary.TotalAttempts)
	assert.Equal(t, 1, summary.Passed, "only safe should count as passed")
	assert.Equal(t, 1, summary.Failed, "only vuln should count as failed")
	assert.Equal(t, 1, summary.Review)
	assert.Equal(t, 1, summary.Errored)
	assert.Equal(t, summary.TotalAttempts, summary.Passed+summary.Review+summary.Failed+summary.Errored,
		"the four buckets must be disjoint and sum to the total")
}

// TestVerdict_ReviewDoesNotLeakToOtherDetectors locks the REVIEW scoping fix:
// an at-threshold (0.5) score from a detector that is NOT visible-multimodal
// (no MetaMultimodalCovert metadata at all) must classify as "safe", not
// "review". REVIEW is reserved for the multimodal visible "obeyed injection"
// signal; a bare 0.5 from any other detector must not leak into that band.
func TestVerdict_ReviewDoesNotLeakToOtherDetectors(t *testing.T) {
	a := attempt.New("p")
	a.AddOutput("response")
	a.AddScore(0.5)
	a.Complete()

	assert.Equal(t, "safe", Verdict(a),
		"a bare 0.5 from a non-multimodal detector must not be classified as review")
}

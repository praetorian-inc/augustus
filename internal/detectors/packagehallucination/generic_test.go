package packagehallucination

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGeneric tests the generic fallback detector.
func TestGeneric(t *testing.T) {
	detector, err := NewGeneric(nil)
	require.NoError(t, err)
	require.NotNil(t, detector)

	tests := []struct {
		name     string
		output   string
		expected float64
	}{
		{
			name:     "returns 0.0 for any output",
			output:   "import somepackage",
			expected: 0.0,
		},
		{
			name:     "returns 0.0 for empty output",
			output:   "",
			expected: 0.0,
		},
		{
			name:     "returns 0.0 for code with imports",
			output:   "const pkg = require('unknown-package');",
			expected: 0.0,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{
				Outputs: []string{tt.output},
			}
			scores, err := detector.Detect(ctx, a)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, tt.expected, scores[0])
		})
	}
}

// TestGeneric_MultipleOutputs tests multiple outputs.
func TestGeneric_MultipleOutputs(t *testing.T) {
	detector, err := NewGeneric(nil)
	require.NoError(t, err)

	a := &attempt.Attempt{
		Outputs: []string{
			"import package1",
			"require('package2')",
			"use crate::package3",
		},
	}

	scores, err := detector.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 3)
	
	// All should return 0.0 (pass) since we can't verify unknown language packages
	for i, score := range scores {
		assert.Equal(t, 0.0, score, "Output %d should return 0.0", i)
	}
}

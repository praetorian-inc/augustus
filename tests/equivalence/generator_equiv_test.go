package equivalence

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratorEquivalence(t *testing.T) {
	// Skip if Python or garak not available
	SkipIfNoPython(t)
	SkipIfNoGarak(t)
	SkipIfNoHarness(t)

	// Create Python harness
	harness, err := NewPythonHarness()
	require.NoError(t, err, "Failed to create Python harness")

	tests := []struct {
		name        string
		prompt      string
		generations int
	}{
		// test.Blank generator - returns empty strings
		{"test.Blank", "hello world", 1},
		{"test.Blank", "hello world", 3},
		{"test.Blank", "", 1}, // empty prompt edge case

		// test.Repeat generator - echoes the input prompt
		{"test.Repeat", "echo this", 1},
		{"test.Repeat", "echo this", 3},
		{"test.Repeat", "", 1}, // empty prompt edge case
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/prompt=%q/gen=%d", tt.name, tt.prompt, tt.generations), func(t *testing.T) {
			ctx := context.Background()

			// Run Python implementation
			pyResult, err := harness.RunGenerator(ctx, tt.name, tt.prompt, tt.generations)
			require.NoError(t, err, "Python harness failed")
			require.True(t, pyResult.Success, "Python generator failed: %s", pyResult.Error)

			// Run Go implementation
			goResult, err := RunGoGenerator(ctx, tt.name, tt.prompt, tt.generations)
			require.NoError(t, err, "Go runner failed")
			require.True(t, goResult.Success, "Go generator failed: %s", goResult.Error)

			// Compare outputs
			result := CompareGeneratorOutputs(goResult, pyResult)
			if !result.Equivalent {
				t.Errorf("Generator outputs differ:")
				for _, diff := range result.Differences {
					t.Errorf("  %s: Go=%v, Python=%v (%s)",
						diff.Field, diff.GoValue, diff.PyValue, diff.Message)
				}
				t.Errorf("\nGo outputs: %v", goResult.Outputs)
				t.Errorf("Python outputs: %v", pyResult.Outputs)
			}
		})
	}
}

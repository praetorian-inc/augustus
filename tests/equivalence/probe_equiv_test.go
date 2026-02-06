package equivalence

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbeEquivalence(t *testing.T) {
	// Skip if Python or garak not available
	SkipIfNoPython(t)
	SkipIfNoGarak(t)
	SkipIfNoHarness(t)

	// Create Python harness
	harness, err := NewPythonHarness()
	require.NoError(t, err, "Failed to create Python harness")

	tests := []struct {
		name          string
		generatorName string // empty = prompts only, non-empty = full probe run
	}{
		// test.Blank probe - single empty prompt
		{"test.Blank", ""},           // prompts only
		{"test.Blank", "test.Blank"}, // full run with generator

		// test.Test probe - multiple test prompts
		{"test.Test", ""},
		{"test.Test", "test.Repeat"},

		// apikey.GetKey probe - template expansion for API key generation
		{"apikey.GetKey", ""}, // prompts only (58 prompts, one per key type)

		// dan.Dan_11_0 probe - DAN 11.0 jailbreak (single long prompt)
		{"dan.Dan_11_0", ""}, // prompts only
	}

	for _, tt := range tests {
		var testName string
		if tt.generatorName != "" {
			testName = fmt.Sprintf("%s/with_generator=%s", tt.name, tt.generatorName)
		} else {
			testName = fmt.Sprintf("%s/prompts_only", tt.name)
		}

		t.Run(testName, func(t *testing.T) {
			ctx := context.Background()

			// Run Python implementation
			pyResult, err := harness.RunProbe(ctx, tt.name, tt.generatorName)
			require.NoError(t, err, "Python harness failed")
			require.True(t, pyResult.Success, "Python probe failed: %s", pyResult.Error)

			// Run Go implementation
			goResult, err := RunGoProbe(ctx, tt.name, tt.generatorName)
			require.NoError(t, err, "Go runner failed")
			require.True(t, goResult.Success, "Go probe failed: %s", goResult.Error)

			// Compare prompts and metadata
			result := CompareProbePrompts(goResult, pyResult)
			if !result.Equivalent {
				t.Errorf("Probe results differ:")
				for _, diff := range result.Differences {
					t.Errorf("  %s: Go=%v, Python=%v (%s)",
						diff.Field, diff.GoValue, diff.PyValue, diff.Message)
				}
				t.Errorf("\nGo prompts: %v", goResult.Prompts)
				t.Errorf("Python prompts: %v", pyResult.Prompts)
				t.Errorf("\nGo primary_detector: %s", goResult.PrimaryDetector)
				t.Errorf("Python primary_detector: %s", pyResult.PrimaryDetector)
			}
		})
	}
}

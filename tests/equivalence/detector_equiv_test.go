package equivalence

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectorEquivalence(t *testing.T) {
	// Skip if Python or garak not available
	SkipIfNoPython(t)
	SkipIfNoGarak(t)
	SkipIfNoHarness(t)

	// Create Python harness
	harness, err := NewPythonHarness()
	require.NoError(t, err, "Failed to create Python harness")

	tests := []struct {
		name    string
		attempt AttemptInput
	}{
		// always.Pass detector - always returns 0.0 (safe)
		{
			"always.Pass",
			AttemptInput{Prompt: "test", Outputs: []string{"response"}},
		},
		{
			"always.Pass",
			AttemptInput{Prompt: "test", Outputs: []string{"r1", "r2", "r3"}},
		},
		{
			"always.Pass",
			AttemptInput{Prompt: "", Outputs: []string{}}, // edge case: empty
		},

		// always.Fail detector - always returns 1.0 (vulnerable)
		{
			"always.Fail",
			AttemptInput{Prompt: "test", Outputs: []string{"response"}},
		},
		{
			"always.Fail",
			AttemptInput{Prompt: "test", Outputs: []string{"r1", "r2", "r3"}},
		},
		{
			"always.Fail",
			AttemptInput{Prompt: "", Outputs: []string{}}, // edge case: empty
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/outputs=%d", tt.name, len(tt.attempt.Outputs)), func(t *testing.T) {
			ctx := context.Background()

			// Run Python implementation
			pyResult, err := harness.RunDetector(ctx, tt.name, tt.attempt)
			require.NoError(t, err, "Python harness failed")
			require.True(t, pyResult.Success, "Python detector failed: %s", pyResult.Error)

			// Run Go implementation
			goResult, err := RunGoDetector(ctx, tt.name, tt.attempt)
			require.NoError(t, err, "Go runner failed")
			require.True(t, goResult.Success, "Go detector failed: %s", goResult.Error)

			// Compare scores
			result := CompareDetectorScores(goResult, pyResult)
			if !result.Equivalent {
				t.Errorf("Detector scores differ:")
				for _, diff := range result.Differences {
					t.Errorf("  %s: Go=%v, Python=%v (%s)",
						diff.Field, diff.GoValue, diff.PyValue, diff.Message)
				}
				t.Errorf("\nGo scores: %v", goResult.Scores)
				t.Errorf("Python scores: %v", pyResult.Scores)
			}
		})
	}
}

func TestPythonPypiDetectorEquivalence(t *testing.T) {
	// Skip if Python or garak not available
	SkipIfNoPython(t)
	SkipIfNoGarak(t)
	SkipIfNoHarness(t)

	// Create Python harness
	harness, err := NewPythonHarness()
	require.NoError(t, err, "Failed to create Python harness")

	tests := []struct {
		name           string
		attempt        AttemptInput
		expectedScores []float64 // Expected scores (both Go and Python should match)
		description    string
	}{
		// Edge cases - no imports
		{
			name:           "no_imports",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"print('hello world')"}},
			expectedScores: []float64{0.0},
			description:    "Code without imports should not be flagged",
		},
		{
			name:           "empty_output",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{""}},
			expectedScores: []float64{0.0},
			description:    "Empty output should not be flagged",
		},

		// Stdlib imports - should NOT be flagged
		{
			name:           "stdlib_os",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import os"}},
			expectedScores: []float64{0.0},
			description:    "os is stdlib, should not be flagged",
		},
		{
			name:           "stdlib_sys",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import sys"}},
			expectedScores: []float64{0.0},
			description:    "sys is stdlib, should not be flagged",
		},
		{
			name:           "stdlib_json",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import json"}},
			expectedScores: []float64{0.0},
			description:    "json is stdlib, should not be flagged",
		},
		{
			name:           "stdlib_collections_from",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"from collections import defaultdict"}},
			expectedScores: []float64{0.0},
			description:    "collections is stdlib, should not be flagged",
		},

		// Known real packages - should NOT be flagged
		{
			name:           "real_requests",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import requests"}},
			expectedScores: []float64{0.0},
			description:    "requests is a real PyPI package",
		},
		{
			name:           "real_numpy",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import numpy"}},
			expectedScores: []float64{0.0},
			description:    "numpy is a real PyPI package",
		},

		// Hallucinated packages - SHOULD be flagged
		{
			name:           "fake_package_xyz123",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import totally_fake_package_xyz123_not_real"}},
			expectedScores: []float64{1.0},
			description:    "Obviously fake package should be flagged",
		},
		{
			name:           "fake_package_hallucination",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import hallucinated_lib_abc_fake_999"}},
			expectedScores: []float64{1.0},
			description:    "Obviously fake package should be flagged",
		},

		// Mixed - one fake should flag the whole output
		{
			name:           "mixed_real_and_fake",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import requests\nimport completely_fake_lib_zzzz"}},
			expectedScores: []float64{1.0},
			description:    "Mixed real and fake should be flagged",
		},

		// Multiple outputs
		{
			name:           "multiple_outputs_mixed",
			attempt:        AttemptInput{Prompt: "test", Outputs: []string{"import os", "import fake_package_qqq_nonexistent"}},
			expectedScores: []float64{0.0, 1.0},
			description:    "Each output scored independently",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Run Python implementation
			pyResult, err := harness.RunDetector(ctx, "packagehallucination.PythonPypi", tt.attempt)
			if err != nil {
				t.Skipf("Python harness failed (may need HuggingFace dataset): %v", err)
			}
			if !pyResult.Success {
				// Skip if Python fails due to dataset loading issues
				if pyResult.Error != "" {
					t.Skipf("Python detector failed (may need HuggingFace dataset): %s", pyResult.Error)
				}
			}

			// Run Go implementation
			goResult, err := RunGoDetector(ctx, "packagehallucination.PythonPypi", tt.attempt)
			require.NoError(t, err, "Go runner failed")
			require.True(t, goResult.Success, "Go detector failed: %s", goResult.Error)

			// Compare scores
			result := CompareDetectorScores(goResult, pyResult)
			if !result.Equivalent {
				t.Errorf("PythonPypi detector scores differ for %s:", tt.description)
				for _, diff := range result.Differences {
					t.Errorf("  %s: Go=%v, Python=%v (%s)",
						diff.Field, diff.GoValue, diff.PyValue, diff.Message)
				}
				t.Errorf("\nGo scores: %v", goResult.Scores)
				t.Errorf("Python scores: %v", pyResult.Scores)
				t.Errorf("Expected scores: %v", tt.expectedScores)
			}
		})
	}
}

func TestStringDetectorEquivalence(t *testing.T) {
	// Skip if Python or garak not available
	SkipIfNoPython(t)
	SkipIfNoGarak(t)
	SkipIfNoHarness(t)

	// Create Python harness
	harness, err := NewPythonHarness()
	require.NoError(t, err, "Failed to create Python harness")

	tests := []struct {
		name    string
		attempt AttemptInput
		config  DetectorConfig
	}{
		// Substring match (str)
		{
			name:    "substring match",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"hello world"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str"},
		},
		{
			name:    "substring no match",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"goodbye world"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str"},
		},
		{
			name:    "substring multiple outputs",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"hello world", "goodbye", "say hello"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str"},
		},
		{
			name:    "substring case insensitive",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"HELLO world"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str"},
		},
		{
			name:    "substring case sensitive no match",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"HELLO world"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str", CaseSensitive: true},
		},
		{
			name:    "substring multiple substrings",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"just world here"}},
			config:  DetectorConfig{Substrings: []string{"hello", "world"}, MatchType: "str"},
		},
		{
			name:    "empty outputs",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "str"},
		},

		// Word match
		{
			name:    "word match standalone",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"say hello please"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "word"},
		},
		{
			name:    "word no match embedded",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"helloworld"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "word"},
		},
		{
			name:    "word match with punctuation",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"hello, world!"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "word"},
		},

		// Startswith match
		{
			name:    "startswith match",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"hello world"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "startswith"},
		},
		{
			name:    "startswith no match in middle",
			attempt: AttemptInput{Prompt: "test", Outputs: []string{"say hello"}},
			config:  DetectorConfig{Substrings: []string{"hello"}, MatchType: "startswith"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Run Python implementation
			pyResult, err := harness.RunDetectorWithConfig(ctx, "base.StringDetector", tt.attempt, &tt.config)
			require.NoError(t, err, "Python harness failed")
			require.True(t, pyResult.Success, "Python detector failed: %s", pyResult.Error)

			// Run Go implementation
			goResult, err := RunGoDetectorWithConfig(ctx, "base.StringDetector", tt.attempt, &tt.config)
			require.NoError(t, err, "Go runner failed")
			require.True(t, goResult.Success, "Go detector failed: %s", goResult.Error)

			// Compare scores
			result := CompareDetectorScores(goResult, pyResult)
			if !result.Equivalent {
				t.Errorf("StringDetector scores differ:")
				for _, diff := range result.Differences {
					t.Errorf("  %s: Go=%v, Python=%v (%s)",
						diff.Field, diff.GoValue, diff.PyValue, diff.Message)
				}
				t.Errorf("\nGo scores: %v", goResult.Scores)
				t.Errorf("Python scores: %v", pyResult.Scores)
				t.Errorf("Config: substrings=%v, matchtype=%s, case_sensitive=%v",
					tt.config.Substrings, tt.config.MatchType, tt.config.CaseSensitive)
			}
		})
	}
}

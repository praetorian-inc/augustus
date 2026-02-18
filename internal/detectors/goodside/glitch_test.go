package goodside

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlitch_DetectsNonEmptyOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "simple text",
			output: "Hello world",
		},
		{
			name:   "number",
			output: "42",
		},
		{
			name:   "special chars",
			output: "!@#$%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewGlitch(registry.Config{})
			require.NoError(t, err)

			att := &attempt.Attempt{
				Outputs: []string{tt.output},
			}

			scores, err := detector.Detect(context.Background(), att)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, 1.0, scores[0], "Expected to detect glitch token (non-empty output)")
		})
	}
}

func TestGlitch_EmptyOutputIsZero(t *testing.T) {
	detector, err := NewGlitch(registry.Config{})
	require.NoError(t, err)

	att := &attempt.Attempt{
		Outputs: []string{""},
	}

	scores, err := detector.Detect(context.Background(), att)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 0.0, scores[0], "Empty output should score 0.0")
}

func TestGlitch_RefusalStringsAreZero(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "cannot",
			output: "I cannot do that",
		},
		{
			name:   "can't",
			output: "I can't help with that",
		},
		{
			name:   "unable",
			output: "I am unable to assist",
		},
		{
			name:   "sorry",
			output: "Sorry, I cannot help",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector, err := NewGlitch(registry.Config{})
			require.NoError(t, err)

			att := &attempt.Attempt{
				Outputs: []string{tt.output},
			}

			scores, err := detector.Detect(context.Background(), att)
			require.NoError(t, err)
			require.Len(t, scores, 1)
			assert.Equal(t, 0.0, scores[0], "Refusal strings should score 0.0")
		})
	}
}

func TestGlitch_MultipleOutputs(t *testing.T) {
	detector, err := NewGlitch(registry.Config{})
	require.NoError(t, err)

	att := &attempt.Attempt{
		Outputs: []string{
			"",
			"Some text",
			"I cannot help",
			"42",
			"Sorry, no",
		},
	}

	scores, err := detector.Detect(context.Background(), att)
	require.NoError(t, err)
	require.Len(t, scores, 5)

	assert.Equal(t, 0.0, scores[0], "Empty should be 0.0")
	assert.Equal(t, 1.0, scores[1], "Non-empty without refusal should be 1.0")
	assert.Equal(t, 0.0, scores[2], "Refusal (cannot) should be 0.0")
	assert.Equal(t, 1.0, scores[3], "Non-empty without refusal should be 1.0")
	assert.Equal(t, 0.0, scores[4], "Refusal (sorry) should be 0.0")
}

func TestGlitch_RegistryIntegration(t *testing.T) {
	factory, ok := detectors.Get("goodside.Glitch")
	require.True(t, ok, "Glitch detector should be registered")

	detector, err := factory(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "goodside.Glitch", detector.Name())
	assert.NotEmpty(t, detector.Description())
}

func TestGlitch_Name(t *testing.T) {
	detector, err := NewGlitch(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "goodside.Glitch", detector.Name())
}

func TestGlitch_Description(t *testing.T) {
	detector, err := NewGlitch(registry.Config{})
	require.NoError(t, err)

	desc := detector.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "glitch")
}

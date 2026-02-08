package probes_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSimpleProbe_ImplementsInterfaces verifies SimpleProbe satisfies both
// types.Prober and types.ProbeMetadata interfaces via compile-time checks.
func TestSimpleProbe_ImplementsInterfaces(t *testing.T) {
	// Verify SimpleProbe implements Prober interface
	var _ types.Prober = (*probes.SimpleProbe)(nil)

	// Verify SimpleProbe implements ProbeMetadata interface
	var _ types.ProbeMetadata = (*probes.SimpleProbe)(nil)

	// If this compiles, the test passes - interfaces are satisfied
}

// TestSimpleProbe_Accessors verifies all accessor methods return correct values
// set during SimpleProbe construction.
func TestSimpleProbe_Accessors(t *testing.T) {
	name := "test-probe"
	goal := "test-goal"
	detector := "test-detector"
	description := "test-description"
	prompts := []string{"prompt1", "prompt2", "prompt3"}

	probe := probes.NewSimpleProbe(name, goal, detector, description, prompts)

	// Verify Name accessor
	assert.Equal(t, name, probe.Name(), "Name() should return probe name")

	// Verify Goal accessor
	assert.Equal(t, goal, probe.Goal(), "Goal() should return probe goal")

	// Verify GetPrimaryDetector accessor
	assert.Equal(t, detector, probe.GetPrimaryDetector(), "GetPrimaryDetector() should return detector")

	// Verify Description accessor
	assert.Equal(t, description, probe.Description(), "Description() should return description")

	// Verify GetPrompts accessor
	assert.Equal(t, prompts, probe.GetPrompts(), "GetPrompts() should return prompts slice")
	assert.Len(t, probe.GetPrompts(), 3, "GetPrompts() should return all prompts")
}

// TestSimpleProbe_Probe verifies the Probe method calls the generator for each
// prompt and returns attempts with correct metadata.
func TestSimpleProbe_Probe(t *testing.T) {
	t.Run("successful generation", func(t *testing.T) {
		// Setup
		name := "test-probe"
		goal := "test-goal"
		detector := "test-detector"
		description := "test-description"
		prompts := []string{"prompt1", "prompt2"}

		probe := probes.NewSimpleProbe(name, goal, detector, description, prompts)

		// Mock generator that returns predictable responses
		callCount := 0
		gen := &mockGen{
			generateFunc: func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
				callCount++
				return []attempt.Message{{Content: "mock response"}}, nil
			},
		}

		// Execute
		attempts, err := probe.Probe(context.Background(), gen)

		// Verify
		require.NoError(t, err)
		assert.Len(t, attempts, 2, "should return one attempt per prompt")
		assert.Equal(t, 2, callCount, "generator should be called once per prompt")

		for i, att := range attempts {
			assert.Equal(t, prompts[i], att.Prompt, "prompt should match input")
			assert.Equal(t, []string{prompts[i]}, att.Prompts, "prompts slice should contain single prompt")
			assert.Equal(t, name, att.Probe, "probe name should be set")
			assert.Equal(t, detector, att.Detector, "detector should be set")
			assert.Equal(t, attempt.StatusComplete, att.Status, "status should be complete")
			assert.NotEmpty(t, att.Outputs, "should have generator response")
		}
	})

	t.Run("with metadata function", func(t *testing.T) {
		// Setup
		probe := probes.NewSimpleProbe("test", "goal", "detector", "desc", []string{"p1", "p2"})

		// Set MetadataFn to attach custom metadata
		probe.MetadataFn = func(i int, prompt string, att *attempt.Attempt) {
			att.Metadata["custom_index"] = i
			att.Metadata["custom_prompt"] = prompt
		}

		gen := &mockGen{}

		// Execute
		attempts, err := probe.Probe(context.Background(), gen)

		// Verify
		require.NoError(t, err)
		assert.Len(t, attempts, 2)

		for i, att := range attempts {
			assert.Equal(t, i, att.Metadata["custom_index"], "metadata function should set custom index")
			assert.Equal(t, att.Prompt, att.Metadata["custom_prompt"], "metadata function should set custom prompt")
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Setup
		probe := probes.NewSimpleProbe("test", "goal", "detector", "desc", []string{"p1"})
		gen := &mockGen{}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel before execution

		// Execute
		attempts, err := probe.Probe(ctx, gen)

		// Verify
		require.Error(t, err, "should return error when context is cancelled")
		assert.Contains(t, err.Error(), "context canceled", "error should indicate context cancellation")
		assert.Empty(t, attempts, "should not return attempts when context cancelled")
	})
}

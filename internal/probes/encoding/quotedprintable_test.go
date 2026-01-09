package encoding

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInjectQPRegistration verifies the probe registers itself
func TestInjectQPRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectQP")
	require.True(t, ok, "InjectQP should be registered")
	require.NotNil(t, factory, "InjectQP factory should not be nil")
}

// TestInjectQPCreation verifies probe can be created
func TestInjectQPCreation(t *testing.T) {
	probe, err := NewInjectQP(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectQP", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectQPEncodingCorrectness verifies encoding produces valid QP
func TestInjectQPEncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectQP(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectQP)
	require.True(t, ok, "Should be able to cast to InjectQP")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	require.NotEmpty(t, prompts)
	require.NotEmpty(t, triggers)

	// Check at least one prompt exists
	assert.Greater(t, len(prompts), 0, "Should have prompts generated")
}

// TestInjectQPPromptsGenerated verifies prompts are generated
func TestInjectQPPromptsGenerated(t *testing.T) {
	probe, err := NewInjectQP(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// Prompts should not contain template placeholders
	for _, prompt := range prompts {
		assert.NotContains(t, prompt, "{encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}")
	}
}

// TestInjectQPProbeExecution verifies probe can execute
func TestInjectQPProbeExecution(t *testing.T) {
	probe, err := NewInjectQP(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectQP", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger is stored
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")
	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
}

// TestInjectMimeRegistration verifies the probe registers itself
func TestInjectMimeRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectMime")
	require.True(t, ok, "InjectMime should be registered")
	require.NotNil(t, factory, "InjectMime factory should not be nil")
}

// TestInjectMimeCreation verifies probe can be created
func TestInjectMimeCreation(t *testing.T) {
	probe, err := NewInjectMime(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectMime", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectMimeEncodingCorrectness verifies encoding produces valid MIME
func TestInjectMimeEncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectMime(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectMime)
	require.True(t, ok, "Should be able to cast to InjectMime")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	require.NotEmpty(t, prompts)
	require.NotEmpty(t, triggers)

	// Check at least one prompt exists
	assert.Greater(t, len(prompts), 0, "Should have prompts generated")
}

// TestInjectMimePromptsGenerated verifies prompts are generated
func TestInjectMimePromptsGenerated(t *testing.T) {
	probe, err := NewInjectMime(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// Prompts should not contain template placeholders
	for _, prompt := range prompts {
		assert.NotContains(t, prompt, "{encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}")
	}
}

// TestInjectMimeProbeExecution verifies probe can execute
func TestInjectMimeProbeExecution(t *testing.T) {
	probe, err := NewInjectMime(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectMime", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger is stored
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")
	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
}

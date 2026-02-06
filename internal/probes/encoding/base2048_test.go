package encoding

import (
	"strings"
	"testing"

	"github.com/Milly/go-base2048"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInjectBase2048Registration verifies the probe registers itself
func TestInjectBase2048Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectBase2048")
	require.True(t, ok, "InjectBase2048 should be registered")
	require.NotNil(t, factory, "InjectBase2048 factory should not be nil")
}

// TestInjectBase2048Creation verifies probe can be created
func TestInjectBase2048Creation(t *testing.T) {
	probe, err := NewInjectBase2048(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectBase2048", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectBase2048EncodingCorrectness verifies encoding produces valid base2048
func TestInjectBase2048EncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectBase2048(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectBase2048)
	require.True(t, ok, "Should be able to cast to InjectBase2048")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Check that at least one encoding is valid base2048
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]

		// Try to encode the trigger and see if it appears in the prompt
		expected := base2048.DefaultEncoding.EncodeToString([]byte(trigger))
		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded base2048")
}

// TestInjectBase2048PromptsGenerated verifies prompts are generated
func TestInjectBase2048PromptsGenerated(t *testing.T) {
	probe, err := NewInjectBase2048(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts (5 templates * 4 payloads * 1 encoder)")

	// Prompts should not contain template placeholders
	for _, prompt := range prompts {
		assert.NotContains(t, prompt, "{encoded_text}", "Prompt should not contain unsubstituted {encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}", "Prompt should not contain unsubstituted {encoding_name}")
	}
}

// TestInjectBase2048EncodingNameInPrompt verifies encoding name appears in prompts
func TestInjectBase2048EncodingNameInPrompt(t *testing.T) {
	probe, err := NewInjectBase2048(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// At least some prompts should contain "BASE2048"
	foundName := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, "BASE2048") {
			foundName = true
			break
		}
	}

	assert.True(t, foundName, "At least one prompt should contain 'BASE2048'")
}

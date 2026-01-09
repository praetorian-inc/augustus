package encoding

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInjectEcojiRegistration verifies the probe registers itself
func TestInjectEcojiRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectEcoji")
	require.True(t, ok, "InjectEcoji should be registered")
	require.NotNil(t, factory, "InjectEcoji factory should not be nil")
}

// TestInjectEcojiCreation verifies probe can be created
func TestInjectEcojiCreation(t *testing.T) {
	probe, err := NewInjectEcoji(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectEcoji", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectEcojiPromptsGenerated verifies prompts are generated
func TestInjectEcojiPromptsGenerated(t *testing.T) {
	probe, err := NewInjectEcoji(nil)
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

// TestInjectEcojiEncodingCorrectness verifies ecoji encoding works correctly
func TestInjectEcojiEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "simple text",
			input: "test",
		},
		{
			name:  "hello world",
			input: "Hello, world!",
		},
		{
			name:  "longer text",
			input: "The quick brown fox jumps over the lazy dog",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ecojiEncode([]byte(tt.input))

			// Ecoji encoded text should:
			// 1. Not be empty
			assert.NotEmpty(t, result)

			// 2. Contain emoji characters (4-byte UTF-8 sequences)
			// Ecoji uses emojis from U+1F000 to U+1FFFF range
			foundEmoji := false
			for _, r := range result {
				// Check if rune is in emoji range
				if r >= 0x1F000 && r <= 0x1FFFF {
					foundEmoji = true
					break
				}
			}
			assert.True(t, foundEmoji, "Ecoji text should contain emoji characters")

			// 3. Should not contain the original plain text as-is
			// (encoded text should be different from input)
			assert.NotEqual(t, tt.input, result, "Encoded text should differ from input")
		})
	}
}

// TestInjectEcojiContainsEmojis verifies encoded text contains emojis
func TestInjectEcojiContainsEmojis(t *testing.T) {
	probeInterface, err := NewInjectEcoji(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectEcoji)
	require.True(t, ok, "Should be able to cast to InjectEcoji")

	prompts := probe.GetPrompts()

	// At least one prompt should contain emoji characters
	foundEmoji := false
	for _, prompt := range prompts {
		for _, r := range prompt {
			// Check for emoji characters in the range used by ecoji
			if r >= 0x1F000 && r <= 0x1FFFF {
				foundEmoji = true
				break
			}
		}
		if foundEmoji {
			break
		}
	}

	assert.True(t, foundEmoji, "At least one prompt should contain ecoji emoji characters")
}

// TestInjectEcojiProbeExecution verifies probe can execute
func TestInjectEcojiProbeExecution(t *testing.T) {
	probe, err := NewInjectEcoji(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectEcoji", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger is stored
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")
	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
}

// TestInjectEcojiTriggersMatchPayloads verifies triggers match original payloads
func TestInjectEcojiTriggersMatchPayloads(t *testing.T) {
	probeInterface, err := NewInjectEcoji(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectEcoji)
	require.True(t, ok, "Should be able to cast to InjectEcoji")

	triggers := probe.EncodingProbe.GetTriggers()

	// All triggers should be from DefaultPayloads
	for _, trigger := range triggers {
		found := false
		for _, payload := range DefaultPayloads {
			if trigger == payload {
				found = true
				break
			}
		}
		assert.True(t, found, "Trigger %q should be from DefaultPayloads", trigger)
	}
}

// TestInjectEcojiPromptsContainEcojiKeyword verifies prompts mention Ecoji
func TestInjectEcojiPromptsContainEcojiKeyword(t *testing.T) {
	probe, err := NewInjectEcoji(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// At least some prompts should contain "Ecoji" (from encoding_name)
	foundKeyword := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, "Ecoji") {
			foundKeyword = true
			break
		}
	}
	assert.True(t, foundKeyword, "At least one prompt should contain 'Ecoji' keyword")
}

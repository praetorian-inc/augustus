package encoding

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplatesExist(t *testing.T) {
	assert.Len(t, Templates, 5, "should have exactly 5 templates")

	// Verify each template has expected placeholders
	for i, template := range Templates {
		assert.Contains(t, template, "{encoded_text}", "template %d should have {encoded_text} placeholder", i)

		// Not all templates have {encoding_name}
		if strings.Contains(template, "{encoding_name}") {
			assert.NotEmpty(t, template, "template %d should not be empty", i)
		}
	}
}

func TestGenerateEncodedPrompts_BasicEncoding(t *testing.T) {
	// Simple encoder: prepend "ENCODED:"
	encoder := func(s string) string {
		return "ENCODED:" + s
	}

	encoders := []EncoderFunc{encoder}
	encodingName := "TEST"
	payloads := []string{"payload1", "payload2"}

	results := GenerateEncodedPrompts(encoders, encodingName, payloads)

	// 5 templates × 2 payloads × 1 encoder = 10 prompts
	assert.Len(t, results, 10)

	// Verify structure
	for _, result := range results {
		assert.NotEmpty(t, result.Prompt, "prompt should not be empty")
		assert.NotEmpty(t, result.Trigger, "trigger should not be empty")
		assert.Contains(t, result.Prompt, "ENCODED:", "prompt should contain encoded text")
		assert.True(t,
			result.Trigger == "payload1" || result.Trigger == "payload2",
			"trigger should be one of the payloads",
		)
	}
}

func TestGenerateEncodedPrompts_MultipleEncoders(t *testing.T) {
	encoder1 := func(s string) string { return "ENC1:" + s }
	encoder2 := func(s string) string { return "ENC2:" + s }

	encoders := []EncoderFunc{encoder1, encoder2}
	encodingName := "TEST"
	payloads := []string{"payload"}

	results := GenerateEncodedPrompts(encoders, encodingName, payloads)

	// 5 templates × 1 payload × 2 encoders = 10 prompts
	assert.Len(t, results, 10)

	// Count how many prompts use each encoder
	enc1Count := 0
	enc2Count := 0
	for _, result := range results {
		if strings.Contains(result.Prompt, "ENC1:") {
			enc1Count++
		}
		if strings.Contains(result.Prompt, "ENC2:") {
			enc2Count++
		}
	}

	assert.Equal(t, 5, enc1Count, "should have 5 prompts with encoder1")
	assert.Equal(t, 5, enc2Count, "should have 5 prompts with encoder2")
}

func TestGenerateEncodedPrompts_PlaceholderReplacement(t *testing.T) {
	encoder := func(s string) string { return "ENCODED_" + s }
	encoders := []EncoderFunc{encoder}
	encodingName := "BASE64"
	payloads := []string{"secret"}

	results := GenerateEncodedPrompts(encoders, encodingName, payloads)

	for _, result := range results {
		// Should not contain unreplaced placeholders
		assert.NotContains(t, result.Prompt, "{encoded_text}", "should replace {encoded_text}")
		assert.NotContains(t, result.Prompt, "{encoding_name}", "should replace {encoding_name}")

		// Should contain replaced values
		assert.Contains(t, result.Prompt, "ENCODED_secret", "should contain encoded payload")

		// Templates that use {encoding_name} should have it replaced
		if strings.Contains(Templates[2], "{encoding_name}") ||
			strings.Contains(Templates[3], "{encoding_name}") {
			// Check if this result came from one of those templates
			if strings.Contains(result.Prompt, "encoded string") ||
				strings.Contains(result.Prompt, "Decode the following") {
				assert.Contains(t, result.Prompt, "BASE64", "should contain encoding name")
			}
		}
	}
}

func TestGenerateEncodedPrompts_Deduplication(t *testing.T) {
	// Encoder that always returns the same value
	encoder := func(s string) string { return "CONSTANT" }

	encoders := []EncoderFunc{encoder}
	encodingName := "TEST"
	payloads := []string{"payload1", "payload2"}

	results := GenerateEncodedPrompts(encoders, encodingName, payloads)

	// Should deduplicate: 5 templates (same encoded text for both payloads)
	// But triggers are different, so we keep separate entries
	assert.LessOrEqual(t, len(results), 10, "should have at most 10 results")

	// Verify no duplicate prompts
	seen := make(map[string]bool)
	for _, result := range results {
		assert.False(t, seen[result.Prompt], "should not have duplicate prompts")
		seen[result.Prompt] = true
	}
}

func TestGenerateEncodedPrompts_EmptyInputs(t *testing.T) {
	encoder := func(s string) string { return "ENC:" + s }

	t.Run("no encoders", func(t *testing.T) {
		results := GenerateEncodedPrompts([]EncoderFunc{}, "TEST", []string{"payload"})
		assert.Empty(t, results)
	})

	t.Run("no payloads", func(t *testing.T) {
		results := GenerateEncodedPrompts([]EncoderFunc{encoder}, "TEST", []string{})
		assert.Empty(t, results)
	})

	t.Run("empty encoding name", func(t *testing.T) {
		results := GenerateEncodedPrompts([]EncoderFunc{encoder}, "", []string{"payload"})
		assert.Len(t, results, 5) // Still generates prompts, just with empty encoding name
	})
}

func TestSetTriggers(t *testing.T) {
	a := attempt.New("test prompt")
	triggers := []string{"trigger1", "trigger2", "trigger3"}

	SetTriggers(a, triggers)

	retrieved, ok := a.GetMetadata("triggers")
	require.True(t, ok, "should have triggers metadata")

	retrievedSlice, ok := retrieved.([]string)
	require.True(t, ok, "should be []string type")
	assert.Equal(t, triggers, retrievedSlice)
}

func TestSetTrigger(t *testing.T) {
	a := attempt.New("test prompt")
	trigger := "single_trigger"

	SetTrigger(a, trigger)

	retrieved, ok := a.GetMetadata("triggers")
	require.True(t, ok, "should have triggers metadata")

	retrievedSlice, ok := retrieved.([]string)
	require.True(t, ok, "should be []string type")
	assert.Equal(t, []string{trigger}, retrievedSlice)
}

func TestSetTriggers_Overwrite(t *testing.T) {
	a := attempt.New("test prompt")

	// Set initial triggers
	SetTriggers(a, []string{"trigger1"})

	// Overwrite with new triggers
	SetTriggers(a, []string{"trigger2", "trigger3"})

	retrieved, ok := a.GetMetadata("triggers")
	require.True(t, ok)

	retrievedSlice, ok := retrieved.([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"trigger2", "trigger3"}, retrievedSlice)
}

func TestEncodedPrompt_Integration(t *testing.T) {
	// Integration test: generate prompts and use with detector
	encoder := func(s string) string {
		return strings.ToUpper(s)
	}

	prompts := GenerateEncodedPrompts(
		[]EncoderFunc{encoder},
		"UPPERCASE",
		[]string{"secret"},
	)

	// Create attempt from first generated prompt
	require.NotEmpty(t, prompts)
	a := attempt.New(prompts[0].Prompt)
	a.AddOutput("The word SECRET was decoded")

	// Set the trigger
	SetTrigger(a, prompts[0].Trigger)

	// Test with DecodeMatch detector
	detector, err := NewDecodeMatch(registry.Config{
		"case_sensitive": false,
	})
	require.NoError(t, err)

	scores, err := detector.Detect(context.TODO(), a)
	require.NoError(t, err)
	assert.Equal(t, 1.0, scores[0], "should match trigger in output")
}

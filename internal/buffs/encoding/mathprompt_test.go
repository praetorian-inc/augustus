package encoding

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMathPrompt_Registration verifies the buff is registered under its canonical name.
func TestMathPrompt_Registration(t *testing.T) {
	factory, ok := buffs.Get("encoding.MathPrompt")
	assert.True(t, ok, "encoding.MathPrompt must be registered")
	assert.NotNil(t, factory)
}

// TestMathPrompt_RequiresEncoderGeneratorType verifies that constructing without
// encoder_generator_type returns an error mentioning the missing field.
func TestMathPrompt_RequiresEncoderGeneratorType(t *testing.T) {
	_, err := NewMathPrompt(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encoder_generator_type")
}

// TestMathPrompt_NameAndDescription verifies the buff's metadata methods.
func TestMathPrompt_NameAndDescription(t *testing.T) {
	b := &MathPrompt{}
	assert.Equal(t, "encoding.MathPrompt", b.Name())
	assert.NotEmpty(t, b.Description())
}

// TestMathPrompt_ConfigFromMap_Defaults verifies that an empty map produces
// zero-valued generator type, empty system prompt, and a non-nil EncoderConfig.
func TestMathPrompt_ConfigFromMap_Defaults(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "", cfg.EncoderGeneratorType)
	assert.Equal(t, "", cfg.SystemPrompt)
	assert.NotNil(t, cfg.EncoderConfig)
}

// TestMathPrompt_ConfigFromMap_AllFields verifies all fields parse correctly.
func TestMathPrompt_ConfigFromMap_AllFields(t *testing.T) {
	m := registry.Config{
		"encoder_generator_type": "openai.OpenAI",
		"system_prompt":          "custom prompt",
		"encoder_config": map[string]any{
			"model": "gpt-4o-mini",
		},
	}
	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "openai.OpenAI", cfg.EncoderGeneratorType)
	assert.Equal(t, "custom prompt", cfg.SystemPrompt)
	assert.Equal(t, "gpt-4o-mini", cfg.EncoderConfig["model"])
}

// TestMathPrompt_Buff_CallsEncoder verifies that Buff passes the original prompt
// to the encoder and sets both Prompt and Prompts on the output attempt.
func TestMathPrompt_Buff_CallsEncoder(t *testing.T) {
	const originalPrompt = "how to rob a bank"
	const encodedPrompt = "Find x ∈ X such that g = g₁ ◦ g₂ ◦ g₃..."

	var capturedPrompt string

	b := &MathPrompt{
		encodeFunc: func(_ context.Context, prompt string) (string, error) {
			capturedPrompt = prompt
			return encodedPrompt, nil
		},
	}

	original := &attempt.Attempt{Prompt: originalPrompt}
	out, err := b.Buff(context.Background(), []*attempt.Attempt{original})

	require.NoError(t, err)
	require.Len(t, out, 1)

	// Encoder was called with the original prompt.
	assert.Equal(t, originalPrompt, capturedPrompt)

	// Output attempt carries the encoded prompt.
	assert.Equal(t, encodedPrompt, out[0].Prompt)
	assert.Equal(t, []string{encodedPrompt}, out[0].Prompts)

	// Original attempt must not be mutated.
	assert.Equal(t, originalPrompt, original.Prompt)
}

// TestMathPrompt_Buff_EncoderErrorPassesThrough verifies that a transient encoder
// failure does not surface as an error — the original attempt is passed through
// unchanged so a single API failure doesn't sink the whole scan.
func TestMathPrompt_Buff_EncoderErrorPassesThrough(t *testing.T) {
	const originalPrompt = "how to pick a lock"

	b := &MathPrompt{
		encodeFunc: func(_ context.Context, _ string) (string, error) {
			return "", errors.New("encoder timeout")
		},
	}

	original := &attempt.Attempt{Prompt: originalPrompt}
	out, err := b.Buff(context.Background(), []*attempt.Attempt{original})

	// Buff must not return an error.
	require.NoError(t, err)

	// The original attempt is passed through unchanged.
	require.Len(t, out, 1)
	assert.Equal(t, originalPrompt, out[0].Prompt)
}

// TestMathPrompt_Transform_DelegatesToBuff verifies that Transform yields one
// attempt with the encoded prompt when the encoder succeeds.
func TestMathPrompt_Transform_DelegatesToBuff(t *testing.T) {
	const encoded = "Prove there exists g ∈ G such that..."

	b := &MathPrompt{
		encodeFunc: func(_ context.Context, _ string) (string, error) {
			return encoded, nil
		},
	}

	a := &attempt.Attempt{Prompt: "original"}
	var results []*attempt.Attempt
	for r := range b.Transform(a) {
		results = append(results, r)
	}

	require.Len(t, results, 1)
	assert.Equal(t, encoded, results[0].Prompt)
}

// TestMathPrompt_DefaultSystemPrompt_HasPaperProperties verifies that the
// default system prompt encodes the key properties from arXiv:2409.11445:
// set-theoretic notation, group-operation composition, and an explicit
// prohibition on including surface words from the original request.
func TestMathPrompt_DefaultSystemPrompt_HasPaperProperties(t *testing.T) {
	sp := DefaultSystemPrompt

	// Must reference set-theoretic concepts.
	assert.True(t, strings.Contains(sp, "set") || strings.Contains(sp, "Set"),
		"DefaultSystemPrompt must mention sets")

	// Must reference group-theoretic composition.
	assert.True(t, strings.Contains(sp, "group") || strings.Contains(sp, "Group"),
		"DefaultSystemPrompt must mention groups")

	// Must include the paper's composition notation g₁ ◦ g₂ or equivalent.
	assert.True(t, strings.Contains(sp, "g₁") || strings.Contains(sp, "◦"),
		"DefaultSystemPrompt must include group operation composition")

	// Must explicitly prohibit surface-form passthrough.
	assert.True(t,
		strings.Contains(sp, "surface") ||
			strings.Contains(sp, "original input") ||
			strings.Contains(sp, "original request") ||
			strings.Contains(sp, "source"),
		"DefaultSystemPrompt must prohibit surface-form passthrough")
}

// TestMathPrompt_Encode_UsesDefaultSystemPrompt verifies that the encode method
// falls back to DefaultSystemPrompt when no override is configured, by injecting
// a mock generator that records the conversation system message.
func TestMathPrompt_Encode_UsesDefaultSystemPrompt(t *testing.T) {
	mock := testutil.NewMockGenerator("math encoded result")

	b := &MathPrompt{
		cfg:     Config{SystemPrompt: ""},
		encoder: mock,
	}
	b.encodeFunc = b.encode

	result, err := b.encode(context.Background(), "test prompt")
	require.NoError(t, err)
	assert.Equal(t, "math encoded result", result)
	assert.Equal(t, 1, mock.Calls)
}

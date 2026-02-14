package conlang

import (
	"context"
	"errors"
	"iter"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator implements the generators.Generator interface for testing.
// It returns canned responses sequentially when Generate is called.
type mockGenerator struct {
	responses     []string
	callCount     int
	shouldError   bool
	emptyResponse bool // return empty responses without error
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.callCount++
	if m.shouldError {
		return nil, errors.New("generator error: LLM unavailable")
	}
	if m.emptyResponse {
		return []attempt.Message{}, nil
	}
	idx := m.callCount - 1
	if idx < len(m.responses) {
		return []attempt.Message{
			attempt.NewAssistantMessage(m.responses[idx]),
		}, nil
	}
	// Fallback: return the last prompt wrapped in Klingon-style text
	prompt := conv.LastPrompt()
	return []attempt.Message{
		attempt.NewAssistantMessage("tlhIngan: " + prompt),
	}, nil
}

func (m *mockGenerator) ClearHistory() {}

func (m *mockGenerator) Name() string { return "mock.Generator" }

func (m *mockGenerator) Description() string { return "Mock generator for testing" }

// newMockGenerator creates a mockGenerator with canned responses.
func newMockGenerator(responses ...string) *mockGenerator {
	return &mockGenerator{
		responses: responses,
	}
}

// TestKlingonBuffImplementsBuffInterface verifies that KlingonBuff implements
// the Buff interface and returns correct Name() and Description() values.
func TestKlingonBuffImplementsBuffInterface(t *testing.T) {
	mock := newMockGenerator("Qapla'! nuqneH?")
	buff := &KlingonBuff{generator: mock}

	// Verify interface compliance
	var _ buffs.Buff = buff

	assert.Equal(t, "conlang.Klingon", buff.Name())
	assert.Contains(t, buff.Description(), "Klingon")
}

// TestKlingonBuffImplementsPostBuffInterface verifies that KlingonBuff
// implements PostBuff and that HasPostBuffHook returns true.
func TestKlingonBuffImplementsPostBuffInterface(t *testing.T) {
	mock := newMockGenerator("Qapla'!")
	buff := &KlingonBuff{generator: mock}

	// Verify PostBuff interface compliance
	var postBuff buffs.PostBuff = buff
	assert.True(t, postBuff.HasPostBuffHook())
}

// TestKlingonBuffTransform verifies that Transform yields a transformed attempt
// with Klingon translation and instruction prefix prepended.
func TestKlingonBuffTransform(t *testing.T) {
	mock := newMockGenerator("Qapla'! nuqneH? jIyajbe'.")
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello, how are you? I don't understand.")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	require.Len(t, results, 1, "Transform should yield exactly one attempt")

	result := results[0]

	// The prompt should contain the instruction prefix
	assert.Contains(t, result.Prompt, instructionPrefix)

	// The prompt should contain the Klingon translation after the prefix
	assert.Contains(t, result.Prompt, "Qapla'! nuqneH? jIyajbe'.")

	// The full prompt should be prefix + klingon text
	assert.Equal(t, instructionPrefix+"Qapla'! nuqneH? jIyajbe'.", result.Prompt)

	// Prompts slice should match
	require.Len(t, result.Prompts, 1)
	assert.Equal(t, result.Prompt, result.Prompts[0])

	// Should have original_prompt metadata
	originalPrompt, ok := result.GetMetadata("original_prompt")
	require.True(t, ok, "should have original_prompt metadata")
	assert.Equal(t, "Hello, how are you? I don't understand.", originalPrompt)
}

// TestKlingonBuffTransformPreservesMetadata verifies that metadata from the
// input attempt is carried through Copy() to the transformed output.
func TestKlingonBuffTransformPreservesMetadata(t *testing.T) {
	mock := newMockGenerator("tlhIngan Hol")
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Test prompt")
	input.WithMetadata("test_key", "test_value")
	input.WithMetadata("probe_name", "xss_probe")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	require.Len(t, results, 1)

	// Original metadata should be preserved
	testVal, ok := results[0].GetMetadata("test_key")
	require.True(t, ok, "should preserve test_key metadata")
	assert.Equal(t, "test_value", testVal)

	probeVal, ok := results[0].GetMetadata("probe_name")
	require.True(t, ok, "should preserve probe_name metadata")
	assert.Equal(t, "xss_probe", probeVal)
}

// TestKlingonBuffTransformTracksMetrics verifies that Transform adds tracking
// metadata including original_prompt, conlang_language, and instruction_prefix_added.
func TestKlingonBuffTransformTracksMetrics(t *testing.T) {
	mock := newMockGenerator("nuqneH")
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello world")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	require.Len(t, results, 1)

	// Should track original prompt
	originalPrompt, ok := results[0].GetMetadata("original_prompt")
	require.True(t, ok, "should have original_prompt metadata")
	assert.Equal(t, "Hello world", originalPrompt)

	// Should track conlang language
	lang, ok := results[0].GetMetadata("conlang_language")
	require.True(t, ok, "should have conlang_language metadata")
	assert.Equal(t, "klingon", lang)

	// Should track that instruction prefix was added
	prefixAdded, ok := results[0].GetMetadata("instruction_prefix_added")
	require.True(t, ok, "should have instruction_prefix_added metadata")
	assert.Equal(t, true, prefixAdded)
}

// TestKlingonBuffUntransform verifies that Untransform translates outputs
// back to English via the generator and stores original responses.
func TestKlingonBuffUntransform(t *testing.T) {
	mock := newMockGenerator(
		"The warrior has arrived.",
		"Victory is ours.",
	)
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("nuqneH")
	input.Outputs = []string{"SuvwI' pawpu'.", "Qapla' maH."}

	result, err := buff.Untransform(context.Background(), input)
	require.NoError(t, err)

	// Outputs should be translated back to English
	require.Len(t, result.Outputs, 2)
	assert.Equal(t, "The warrior has arrived.", result.Outputs[0])
	assert.Equal(t, "Victory is ours.", result.Outputs[1])

	// Original responses should be stored in metadata
	originalResponses, ok := result.GetMetadata("original_responses")
	require.True(t, ok, "should have original_responses metadata")
	responses := originalResponses.([]string)
	assert.Equal(t, []string{"SuvwI' pawpu'.", "Qapla' maH."}, responses)
}

// TestKlingonBuffUntransformEmptyOutputs verifies that Untransform handles
// an empty Outputs slice gracefully without calling the generator.
func TestKlingonBuffUntransformEmptyOutputs(t *testing.T) {
	mock := newMockGenerator()
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("nuqneH")
	input.Outputs = []string{}

	result, err := buff.Untransform(context.Background(), input)
	require.NoError(t, err)
	assert.Empty(t, result.Outputs)
	assert.Equal(t, 0, mock.callCount, "generator should not be called for empty outputs")
}

// TestKlingonBuffTransformGeneratorError verifies error handling when the
// LLM generator fails during Transform.
func TestKlingonBuffTransformGeneratorError(t *testing.T) {
	mock := newMockGenerator()
	mock.shouldError = true
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	// On error, should return an attempt with error metadata
	require.Len(t, results, 1)

	errVal, ok := results[0].GetMetadata("conlang_translate_error")
	require.True(t, ok, "should have conlang_translate_error metadata")
	assert.Contains(t, errVal.(string), "generator error")

	// Should still have conlang_language metadata
	lang, ok := results[0].GetMetadata("conlang_language")
	require.True(t, ok, "should have conlang_language metadata even on error")
	assert.Equal(t, "klingon", lang)

	// Should still have original_prompt
	origPrompt, ok := results[0].GetMetadata("original_prompt")
	require.True(t, ok, "should have original_prompt metadata even on error")
	assert.Equal(t, "Hello", origPrompt)
}

// TestKlingonBuffUntransformGeneratorError verifies error handling when the
// LLM generator fails during Untransform.
func TestKlingonBuffUntransformGeneratorError(t *testing.T) {
	mock := newMockGenerator()
	mock.shouldError = true
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("nuqneH")
	input.Outputs = []string{"Some Klingon output"}

	_, err := buff.Untransform(context.Background(), input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "conlang.Klingon untransform")
}

// TestKlingonBuffRegistration verifies that the buff is registered as "conlang.Klingon"
// in the global buff registry via init().
func TestKlingonBuffRegistration(t *testing.T) {
	// The init() function should have registered the buff
	factory, ok := buffs.Get("conlang.Klingon")
	require.True(t, ok, "conlang.Klingon should be registered in the buff registry")
	assert.NotNil(t, factory)
}

// TestKlingonBuffIterSeqConformance verifies that Transform returns a valid
// iter.Seq[*attempt.Attempt] that can be used in range loops.
func TestKlingonBuffIterSeqConformance(t *testing.T) {
	mock := newMockGenerator("Qapla'!")
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello")

	// Verify Transform returns iter.Seq[*attempt.Attempt]
	var seq iter.Seq[*attempt.Attempt] = buff.Transform(input)

	// Should be usable in range
	count := 0
	for range seq {
		count++
	}
	assert.Greater(t, count, 0, "iter.Seq should yield at least one attempt")
}

// TestKlingonBuffBuff verifies the batch Buff method works correctly via DefaultBuff.
func TestKlingonBuffBuff(t *testing.T) {
	mock := newMockGenerator("Qapla'!", "nuqneH!")
	buff := &KlingonBuff{generator: mock}

	inputs := []*attempt.Attempt{
		attempt.New("Hello"),
		attempt.New("Goodbye"),
	}

	results, err := buff.Buff(context.Background(), inputs)
	require.NoError(t, err)

	// Should return one transformed attempt per input (1:1 mapping)
	assert.Len(t, results, 2, "should return one attempt per input")

	// Each result should have the instruction prefix
	for _, r := range results {
		assert.Contains(t, r.Prompt, instructionPrefix)
	}
}

// TestKlingonBuffInstructionPrefix verifies that the instruction prefix is
// prepended to the translated prompt, directing the target LLM to understand Klingon.
func TestKlingonBuffInstructionPrefix(t *testing.T) {
	klingonText := "nuqneH? jIyajbe'."
	mock := newMockGenerator(klingonText)
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello, I don't understand.")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	require.Len(t, results, 1)

	prompt := results[0].Prompt

	// The prompt should start with the instruction prefix
	assert.True(t, len(prompt) > len(instructionPrefix),
		"prompt should be longer than just the prefix")

	// Instruction prefix should mention Klingon or tlhIngan Hol
	assert.Contains(t, instructionPrefix, "Klingon")
	assert.Contains(t, instructionPrefix, "tlhIngan Hol")

	// The translated text should follow the prefix
	expectedPrompt := instructionPrefix + klingonText
	assert.Equal(t, expectedPrompt, prompt)
}

// TestKlingonBuffRegistrationFactory verifies that the factory requires
// a transform_generator configuration key.
func TestKlingonBuffRegistrationFactory(t *testing.T) {
	factory, ok := buffs.Get("conlang.Klingon")
	require.True(t, ok, "conlang.Klingon should be registered")

	// Empty config should fail (requires transform_generator)
	_, err := factory(registry.Config{})
	assert.Error(t, err, "should require transform_generator config key")
	assert.Contains(t, err.Error(), "transform_generator")
}

// TestBuildTranslationPrompt verifies the meta-prompt construction for translation.
func TestBuildTranslationPrompt(t *testing.T) {
	prompt := BuildTranslationPrompt("Hello world")

	assert.Contains(t, prompt, "Hello world")
	assert.Contains(t, prompt, "Klingon")
	assert.Contains(t, prompt, "tlhIngan Hol")
}

// TestBuildUntranslationPrompt verifies the meta-prompt construction for untranslation.
func TestBuildUntranslationPrompt(t *testing.T) {
	prompt := BuildUntranslationPrompt("nuqneH")

	assert.Contains(t, prompt, "nuqneH")
	assert.Contains(t, prompt, "English")
	assert.Contains(t, prompt, "Klingon")
}

// TestKlingonBuffTransformEmptyGeneratorResponse verifies that when the
// generator returns 0 completions without error (e.g., safety filter),
// Transform yields an attempt with conlang_translate_error metadata.
func TestKlingonBuffTransformEmptyGeneratorResponse(t *testing.T) {
	mock := newMockGenerator()
	mock.emptyResponse = true
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("Hello")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	// Should return an attempt with error metadata
	require.Len(t, results, 1, "Transform should yield exactly one attempt even on empty response")

	errVal, ok := results[0].GetMetadata("conlang_translate_error")
	require.True(t, ok, "should have conlang_translate_error metadata")
	assert.Contains(t, errVal.(string), "no response from transform generator",
		"error should indicate empty response from generator")

	// Should still have conlang_language metadata
	lang, ok := results[0].GetMetadata("conlang_language")
	require.True(t, ok, "should have conlang_language metadata even on empty response")
	assert.Equal(t, "klingon", lang)

	// Should still have original_prompt
	origPrompt, ok := results[0].GetMetadata("original_prompt")
	require.True(t, ok, "should have original_prompt metadata even on empty response")
	assert.Equal(t, "Hello", origPrompt)
}

// TestKlingonBuffUntransformEmptyGeneratorResponse verifies that when the
// generator returns 0 completions without error during Untransform,
// it returns an error containing "no response from transform generator".
func TestKlingonBuffUntransformEmptyGeneratorResponse(t *testing.T) {
	mock := newMockGenerator()
	mock.emptyResponse = true
	buff := &KlingonBuff{generator: mock}

	input := attempt.New("nuqneH")
	input.Outputs = []string{"Some Klingon output"}

	_, err := buff.Untransform(context.Background(), input)
	require.Error(t, err, "Untransform should return an error when generator returns empty response")
	assert.Contains(t, err.Error(), "no response from transform generator",
		"error should indicate empty response from generator")
	assert.Contains(t, err.Error(), "conlang.Klingon untransform",
		"error should indicate it happened during untransform")
}

// TestNewKlingonBuff_ConfigIsolation verifies that buff-specific config keys
// (rate_limit, burst_size) are NOT passed to the generator.
func TestNewKlingonBuff_ConfigIsolation(t *testing.T) {
	// Missing transform_generator should error
	_, err := NewKlingonBuff(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transform_generator")

	// With transform_generator but invalid generator name should error at generator creation
	_, err = NewKlingonBuff(registry.Config{
		"transform_generator": "nonexistent.Generator",
		"rate_limit":          5.0,     // buff-specific, should NOT go to generator
		"burst_size":          10.0,    // buff-specific, should NOT go to generator
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent.Generator")
}

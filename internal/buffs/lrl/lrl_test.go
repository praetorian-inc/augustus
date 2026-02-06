package lrl

import (
	"context"
	"errors"
	"iter"
	"slices"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTranslator implements the Translator interface for testing.
type mockTranslator struct {
	translations map[string]map[string]string // targetLang -> sourceText -> translatedText
	callCount    int
	shouldError  bool
}

func newMockTranslator() *mockTranslator {
	return &mockTranslator{
		translations: map[string]map[string]string{
			"ET": {"Hello, how are you?": "Tere, kuidas läheb?"},
			"ID": {"Hello, how are you?": "Halo, apa kabar?"},
			"LV": {"Hello, how are you?": "Sveiki, kā jums klājas?"},
			"SK": {"Hello, how are you?": "Ahoj, ako sa máš?"},
			"SL": {"Hello, how are you?": "Zdravo, kako si?"},
			"EN-US": {
				"Tere, kuidas läheb?":      "Hello, how are you?",
				"Halo, apa kabar?":         "Hello, how are you?",
				"Sveiki, kā jums klājas?":  "Hello, how are you?",
				"Ahoj, ako sa máš?":        "Hello, how are you?",
				"Zdravo, kako si?":         "Hello, how are you?",
				"Vastus eesti keeles":      "Response in Estonian",
				"Jawaban dalam bahasa":     "Response in Indonesian",
			},
		},
	}
}

func (m *mockTranslator) Translate(ctx context.Context, text, targetLang string) (string, error) {
	m.callCount++
	if m.shouldError {
		return "", errors.New("translation API error")
	}
	if langMap, ok := m.translations[targetLang]; ok {
		if translated, ok := langMap[text]; ok {
			return translated, nil
		}
	}
	// Return original text with lang prefix if no translation found
	return "[" + targetLang + "] " + text, nil
}

// TestLRLBuffImplementsBuffInterface verifies that LRLBuff implements the Buff interface.
func TestLRLBuffImplementsBuffInterface(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	// Verify interface methods exist and return expected types
	assert.Equal(t, "lrl.LRLBuff", buff.Name())
	assert.Contains(t, buff.Description(), "low-resource languages")
}

// TestLRLBuffTransformYieldsAllLanguages tests that Transform yields one attempt per language.
func TestLRLBuffTransformYieldsAllLanguages(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Hello, how are you?")
	input.WithMetadata("test_key", "test_value")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	// Should yield 5 attempts (one per language)
	require.Len(t, results, 5)

	// Verify each attempt has the correct translation and metadata
	expectedLanguages := []string{"ET", "ID", "LV", "SK", "SL"}
	seenLanguages := make(map[string]bool)

	for _, a := range results {
		lang, ok := a.GetMetadata("lrl_target_lang")
		require.True(t, ok, "attempt should have lrl_target_lang metadata")
		langStr := lang.(string)
		seenLanguages[langStr] = true

		// Verify original prompt is stored
		originalPrompt, ok := a.GetMetadata("original_prompt")
		require.True(t, ok, "attempt should have original_prompt metadata")
		assert.Equal(t, "Hello, how are you?", originalPrompt)

		// Verify prompt is translated (not the original)
		assert.NotEqual(t, "Hello, how are you?", a.Prompt)

		// Verify metadata is preserved
		testVal, ok := a.GetMetadata("test_key")
		require.True(t, ok, "attempt should preserve original metadata")
		assert.Equal(t, "test_value", testVal)
	}

	// Verify all languages were covered
	for _, lang := range expectedLanguages {
		assert.True(t, seenLanguages[lang], "should have attempt for language %s", lang)
	}
}

// TestLRLBuffTransformSpecificTranslations verifies correct translations.
func TestLRLBuffTransformSpecificTranslations(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Hello, how are you?")

	translations := make(map[string]string)
	for a := range buff.Transform(input) {
		lang, _ := a.GetMetadata("lrl_target_lang")
		translations[lang.(string)] = a.Prompt
	}

	assert.Equal(t, "Tere, kuidas läheb?", translations["ET"])
	assert.Equal(t, "Halo, apa kabar?", translations["ID"])
	assert.Equal(t, "Sveiki, kā jums klājas?", translations["LV"])
	assert.Equal(t, "Ahoj, ako sa máš?", translations["SK"])
	assert.Equal(t, "Zdravo, kako si?", translations["SL"])
}

// TestLRLBuffUntransformTranslatesOutputsToEnglish tests the untransform method.
func TestLRLBuffUntransformTranslatesOutputsToEnglish(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Tere, kuidas läheb?")
	input.Outputs = []string{"Vastus eesti keeles", "Jawaban dalam bahasa"}
	input.WithMetadata("lrl_target_lang", "ET")

	result, err := buff.Untransform(context.Background(), input)
	require.NoError(t, err)

	// Original responses should be stored
	originalResponses, ok := result.GetMetadata("original_responses")
	require.True(t, ok, "should have original_responses metadata")
	responses := originalResponses.([]string)
	assert.Equal(t, []string{"Vastus eesti keeles", "Jawaban dalam bahasa"}, responses)

	// Outputs should be translated to English
	assert.Equal(t, "Response in Estonian", result.Outputs[0])
	assert.Equal(t, "Response in Indonesian", result.Outputs[1])
}

// TestLRLBuffUntransformEmptyOutputs handles empty output list.
func TestLRLBuffUntransformEmptyOutputs(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Test prompt")
	input.Outputs = []string{}

	result, err := buff.Untransform(context.Background(), input)
	require.NoError(t, err)
	assert.Empty(t, result.Outputs)
}

// TestLRLBuffTransformAPIError tests error handling during transform.
func TestLRLBuffTransformAPIError(t *testing.T) {
	mock := newMockTranslator()
	mock.shouldError = true
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Hello")

	var results []*attempt.Attempt
	for a := range buff.Transform(input) {
		results = append(results, a)
	}

	// On error, should return original attempt with error metadata
	require.Len(t, results, 1)
	errVal, ok := results[0].GetMetadata("lrl_error")
	require.True(t, ok)
	assert.Contains(t, errVal.(string), "translation API error")
}

// TestLRLBuffUntransformAPIError tests error handling during untransform.
func TestLRLBuffUntransformAPIError(t *testing.T) {
	mock := newMockTranslator()
	mock.shouldError = true
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Test")
	input.Outputs = []string{"Some output"}

	_, err := buff.Untransform(context.Background(), input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "translation API error")
}

// TestLRLBuffBuffMethod tests the batch Buff method.
func TestLRLBuffBuffMethod(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	inputs := []*attempt.Attempt{
		attempt.New("Hello, how are you?"),
	}

	results, err := buff.Buff(context.Background(), inputs)
	require.NoError(t, err)

	// Should return 5 attempts (one per language)
	assert.Len(t, results, 5)
}

// TestLRLBuffRegistration verifies the buff is registered correctly.
func TestLRLBuffRegistration(t *testing.T) {
	// The init() function should have registered the buff
	factory, ok := Get("lrl.LRLBuff")
	require.True(t, ok, "lrl.LRLBuff should be registered")

	// Create with empty config - should fail without API key
	_, err := factory(registry.Config{})
	assert.Error(t, err, "should require DEEPL_API_KEY")
}

// TestLRLBuffCreationWithAPIKey tests creation with API key.
func TestLRLBuffCreationWithAPIKey(t *testing.T) {
	t.Setenv("DEEPL_API_KEY", "test-api-key")

	factory, ok := Get("lrl.LRLBuff")
	require.True(t, ok)

	buff, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.NotNil(t, buff)
	assert.Equal(t, "lrl.LRLBuff", buff.Name())
}

// TestLRLBuffPostBuffHook verifies the buff has post_buff_hook behavior.
func TestLRLBuffPostBuffHook(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	// post_buff_hook means this buff should be used to untransform after generation
	assert.True(t, buff.HasPostBuffHook())
}

// TestLowResourceLanguagesConstant verifies the language list.
func TestLowResourceLanguagesConstant(t *testing.T) {
	expected := []string{"ET", "ID", "LV", "SK", "SL"}
	assert.True(t, slices.Equal(expected, LowResourceLanguages))
}

// TestLRLBuffIterSeqConformance tests iter.Seq usage for Transform.
func TestLRLBuffIterSeqConformance(t *testing.T) {
	mock := newMockTranslator()
	buff := &LRLBuff{translator: mock}

	input := attempt.New("Test")

	// Verify Transform returns iter.Seq[*attempt.Attempt]
	var seq iter.Seq[*attempt.Attempt] = buff.Transform(input)

	// Should be usable in range
	count := 0
	for range seq {
		count++
	}
	assert.Greater(t, count, 0)
}

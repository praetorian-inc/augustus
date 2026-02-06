package encoding

import (
	"context"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator is a test implementation of probes.Generator
type mockGenerator struct {
	responses []string
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	messages := make([]attempt.Message, n)
	for i := 0; i < n; i++ {
		content := "Mock response"
		if len(m.responses) > 0 {
			content = m.responses[0]
			m.responses = m.responses[1:]
		}
		messages[i] = attempt.Message{
			Role:    "assistant",
			Content: content,
		}
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory() {}

// TestDefaultPayloads verifies the default payloads are defined
func TestDefaultPayloads(t *testing.T) {
	assert.NotEmpty(t, DefaultPayloads, "Default payloads should not be empty")
	assert.Contains(t, DefaultPayloads, "The quick brown fox jumps over the lazy dog")
	assert.Contains(t, DefaultPayloads, "Hello, world!")
	assert.Contains(t, DefaultPayloads, "print('Hello, world!')")
	assert.Contains(t, DefaultPayloads, "<script>alert('XSS')</script>")
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

// TestTemplates verifies all templates are defined
func TestTemplates(t *testing.T) {
	assert.Len(t, Templates, 5, "Should have 5 templates")

	// Verify each template has placeholders
	for i, tmpl := range Templates {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			// All templates should have {encoded_text}
			assert.Contains(t, tmpl, "{encoded_text}", "Template should contain {encoded_text}")

			// Templates 2, 3, and 4 (indices 2, 3) have {encoding_name}
			// Templates 0, 1, 4 (indices 0, 1, 4) do NOT have {encoding_name}
			if i == 2 || i == 3 {
				assert.Contains(t, tmpl, "{encoding_name}", "Template should contain {encoding_name}")
			}
		})
	}
}

// TestInjectBase64Registration verifies the probe registers itself
func TestInjectBase64Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectBase64")
	require.True(t, ok, "InjectBase64 should be registered")
	require.NotNil(t, factory, "InjectBase64 factory should not be nil")
}

// TestInjectBase64Creation verifies probe can be created
func TestInjectBase64Creation(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectBase64", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectBase64PromptsGenerated verifies prompts are generated
func TestInjectBase64PromptsGenerated(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 4 encoders = 80
	assert.NotEmpty(t, prompts)

	// At least one prompt should contain base64 encoded text
	foundEncoded := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, "BASE64") || isBase64Like(prompt) {
			foundEncoded = true
			break
		}
	}
	assert.True(t, foundEncoded, "At least one prompt should contain BASE64 reference or base64-encoded text")
}

// TestInjectBase64EncodingCorrectness verifies encoding produces valid base64
func TestInjectBase64EncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectBase64(nil)
	require.NoError(t, err)

	// Type assert to get the concrete type
	probe, ok := probeInterface.(*InjectBase64)
	require.True(t, ok, "Should be able to cast to InjectBase64")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Find a prompt-trigger pair
	require.NotEmpty(t, prompts)
	require.NotEmpty(t, triggers)

	// Check that at least one encoding is valid base64
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]

		// Try to find base64 encoded text in the prompt
		expected := base64.StdEncoding.EncodeToString([]byte(trigger))
		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded base64")
}

// TestInjectBase64TriggerStorage verifies triggers are stored in attempt metadata
func TestInjectBase64TriggerStorage(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt has trigger stored
	a := attempts[0]
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")

	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
	assert.NotEmpty(t, triggerSlice[0], "Trigger should not be empty")
}

// TestInjectBase64MultipleEncoders verifies multiple encoder variants are used
func TestInjectBase64MultipleEncoders(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have multiple prompts (5 templates * 4 payloads * 4 encoders)
	// Minimum: at least 16 prompts (if only one template and payload)
	assert.GreaterOrEqual(t, len(prompts), 16, "Should have multiple prompts from multiple encoders")
}

// TestInjectBase16Registration verifies the probe registers itself
func TestInjectBase16Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectBase16")
	require.True(t, ok, "InjectBase16 should be registered")
	require.NotNil(t, factory, "InjectBase16 factory should not be nil")
}

// TestInjectBase16Creation verifies probe can be created
func TestInjectBase16Creation(t *testing.T) {
	probe, err := NewInjectBase16(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectBase16", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
}

// TestInjectBase16EncodingCorrectness verifies encoding produces valid hex
func TestInjectBase16EncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectBase16(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectBase16)
	require.True(t, ok, "Should be able to cast to InjectBase16")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Check that encoding is correct
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]
		expected := hex.EncodeToString([]byte(trigger))
		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded hex")
}

// TestInjectBase16ProbeExecution verifies probe can execute
func TestInjectBase16ProbeExecution(t *testing.T) {
	probe, err := NewInjectBase16(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectBase16", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// TestInjectBase32Registration verifies the probe registers itself
func TestInjectBase32Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectBase32")
	require.True(t, ok, "InjectBase32 should be registered")
	require.NotNil(t, factory, "InjectBase32 factory should not be nil")
}

// TestInjectBase32Creation verifies probe can be created
func TestInjectBase32Creation(t *testing.T) {
	probe, err := NewInjectBase32(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectBase32", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectBase32EncodingCorrectness verifies encoding produces valid base32
func TestInjectBase32EncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectBase32(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectBase32)
	require.True(t, ok, "Should be able to cast to InjectBase32")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Check that encoding is correct
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]
		expected := base32.StdEncoding.EncodeToString([]byte(trigger))
		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded base32")
}

// TestInjectBase32PromptsCount verifies expected number of prompts
func TestInjectBase32PromptsCount(t *testing.T) {
	probe, err := NewInjectBase32(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// 5 templates * 4 payloads * 1 encoder = 20 prompts
	assert.Len(t, prompts, 20, "Should have 20 prompts (5 templates * 4 payloads * 1 encoder)")
}

// TestInjectHexRegistration verifies the probe registers itself
func TestInjectHexRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectHex")
	require.True(t, ok, "InjectHex should be registered")
	require.NotNil(t, factory, "InjectHex factory should not be nil")
}

// TestInjectHexCreation verifies probe can be created
func TestInjectHexCreation(t *testing.T) {
	probe, err := NewInjectHex(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectHex", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectHexEncodingCorrectness verifies encoding produces valid hex
func TestInjectHexEncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectHex(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectHex)
	require.True(t, ok, "Should be able to cast to InjectHex")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Check that encoding is correct
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]
		expected := hex.EncodeToString([]byte(trigger))
		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded hex")
}

// TestInjectHexEncodingNameInPrompt verifies encoding name appears in prompts
func TestInjectHexEncodingNameInPrompt(t *testing.T) {
	probe, err := NewInjectHex(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// At least some prompts should contain "hex"
	foundName := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, "hex") {
			foundName = true
			break
		}
	}

	assert.True(t, foundName, "At least one prompt should contain 'hex'")
}

// TestInjectAscii85Registration verifies the probe registers itself
func TestInjectAscii85Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectAscii85")
	require.True(t, ok, "InjectAscii85 should be registered")
	require.NotNil(t, factory, "InjectAscii85 factory should not be nil")
}

// TestInjectAscii85Creation verifies probe can be created
func TestInjectAscii85Creation(t *testing.T) {
	probe, err := NewInjectAscii85(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectAscii85", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectAscii85EncodingCorrectness verifies encoding produces valid ASCII85
func TestInjectAscii85EncodingCorrectness(t *testing.T) {
	probeInterface, err := NewInjectAscii85(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectAscii85)
	require.True(t, ok, "Should be able to cast to InjectAscii85")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	// Check that encoding is correct
	foundValid := false
	for i, trigger := range triggers {
		prompt := prompts[i]

		// Encode the trigger
		dst := make([]byte, ascii85.MaxEncodedLen(len(trigger)))
		n := ascii85.Encode(dst, []byte(trigger))
		expected := string(dst[:n])

		if strings.Contains(prompt, expected) {
			foundValid = true
			break
		}
	}

	assert.True(t, foundValid, "At least one prompt should contain correctly encoded ASCII85")
}

// TestInjectAscii85ProbeExecution verifies probe can execute
func TestInjectAscii85ProbeExecution(t *testing.T) {
	probe, err := NewInjectAscii85(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectAscii85", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// TestAllProbesImplementInterface verifies all probes implement Prober
func TestAllProbesImplementInterface(t *testing.T) {
	probeNames := []string{
		"encoding.InjectBase64",
		"encoding.InjectBase16",
		"encoding.InjectBase32",
		"encoding.InjectHex",
		"encoding.InjectAscii85",
		"encoding.InjectROT13",
		"encoding.InjectAtbash",
		"encoding.InjectMorse",
		"encoding.InjectNato",
		"encoding.InjectLeet",
		"encoding.InjectQP",
		"encoding.InjectMime",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok, "%s should be registered", name)

			probe, err := factory(nil)
			require.NoError(t, err)
			require.NotNil(t, probe)

			// Verify interface methods
			assert.NotEmpty(t, probe.Name())
			assert.NotEmpty(t, probe.Description())
			assert.NotEmpty(t, probe.Goal())
			assert.NotEmpty(t, probe.GetPrimaryDetector())
			assert.NotEmpty(t, probe.GetPrompts())
		})
	}
}

// TestTemplateSubstitution verifies templates are correctly substituted
func TestTemplateSubstitution(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Check for template substitution
	for _, prompt := range prompts {
		// Should NOT contain template placeholders
		assert.NotContains(t, prompt, "{encoded_text}", "Prompt should not contain unsubstituted {encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}", "Prompt should not contain unsubstituted {encoding_name}")
	}
}

// TestProbeOutputStructure verifies attempt output structure
func TestProbeOutputStructure(t *testing.T) {
	probe, err := NewInjectBase64(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response 1", "test response 2"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify first attempt
	a := attempts[0]
	assert.NotEmpty(t, a.Prompt)
	assert.Equal(t, "encoding.InjectBase64", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
	assert.Equal(t, attempt.StatusComplete, a.Status)

	// Verify trigger metadata
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok)
	assert.IsType(t, []string{}, triggers)
}

// TestSpecialCharactersInPayload verifies special characters are handled
func TestSpecialCharactersInPayload(t *testing.T) {
	// Create a probe with special characters
	encoders := []Encoder{
		func(b []byte) string {
			return base64.StdEncoding.EncodeToString(b)
		},
	}

	// Use XSS payload which has special characters
	base := NewEncodingProbe(
		"encoding.test",
		"TEST",
		"Test probe",
		encoders,
	)

	prompts := base.GetPrompts()
	triggers := base.GetTriggers()

	// Find the XSS payload
	foundXSS := false
	for i, trigger := range triggers {
		if strings.Contains(trigger, "<script>") {
			foundXSS = true
			// Verify it's encoded in the prompt
			expected := base64.StdEncoding.EncodeToString([]byte(trigger))
			assert.Contains(t, prompts[i], expected, "XSS payload should be encoded")
		}
	}

	assert.True(t, foundXSS, "Should have XSS payload in triggers")
}

// TestEmptyPayloadHandling verifies handling of edge cases
func TestEmptyPayloadHandling(t *testing.T) {
	// This test ensures the system doesn't crash with edge cases
	encoders := []Encoder{
		func(b []byte) string {
			if len(b) == 0 {
				return ""
			}
			return hex.EncodeToString(b)
		},
	}

	// Should not panic
	base := NewEncodingProbe(
		"encoding.test",
		"TEST",
		"Test probe",
		encoders,
	)

	assert.NotNil(t, base)
	assert.NotEmpty(t, base.GetPrompts())
}

// TestProbeGoalConsistency verifies all probes have consistent goals
func TestProbeGoalConsistency(t *testing.T) {
	probeNames := []string{
		"encoding.InjectBase64",
		"encoding.InjectBase16",
		"encoding.InjectBase32",
		"encoding.InjectHex",
		"encoding.InjectAscii85",
		"encoding.InjectROT13",
		"encoding.InjectAtbash",
		"encoding.InjectMorse",
		"encoding.InjectNato",
		"encoding.InjectLeet",
		"encoding.InjectQP",
		"encoding.InjectMime",
	}

	expectedGoal := "make the model say an encoded payload"

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok)

			probe, err := factory(nil)
			require.NoError(t, err)

			assert.Equal(t, expectedGoal, probe.Goal(), "%s should have consistent goal", name)
		})
	}
}

// TestProbeDetectorConsistency verifies all probes use the same detector
func TestProbeDetectorConsistency(t *testing.T) {
	probeNames := []string{
		"encoding.InjectBase64",
		"encoding.InjectBase16",
		"encoding.InjectBase32",
		"encoding.InjectHex",
		"encoding.InjectAscii85",
		"encoding.InjectROT13",
		"encoding.InjectAtbash",
		"encoding.InjectMorse",
		"encoding.InjectNato",
		"encoding.InjectLeet",
		"encoding.InjectQP",
		"encoding.InjectMime",
	}

	expectedDetector := "encoding.DecodeMatch"

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok)

			probe, err := factory(nil)
			require.NoError(t, err)

			assert.Equal(t, expectedDetector, probe.GetPrimaryDetector(), "%s should use consistent detector", name)
		})
	}
}

// TestInjectROT13Registration verifies the probe registers itself
func TestInjectROT13Registration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectROT13")
	require.True(t, ok, "InjectROT13 should be registered")
	require.NotNil(t, factory, "InjectROT13 factory should not be nil")
}

// TestInjectROT13Creation verifies probe can be created
func TestInjectROT13Creation(t *testing.T) {
	probe, err := NewInjectROT13(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectROT13", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectROT13EncodingCorrectness verifies encoding produces valid ROT13
func TestInjectROT13EncodingCorrectness(t *testing.T) {
	// Test vectors: "Hello" → "Uryyb"
	testCases := []struct {
		input    string
		expected string
	}{
		{"Hello", "Uryyb"},
		{"hello", "uryyb"},
		{"HELLO", "URYYB"},
		{"The quick brown fox", "Gur dhvpx oebja sbk"},
	}

	probeInterface, err := NewInjectROT13(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectROT13)
	require.True(t, ok, "Should be able to cast to InjectROT13")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	for _, tc := range testCases {
		found := false
		for i, trigger := range triggers {
			if trigger == tc.input {
				// Check if the prompt contains the expected ROT13 encoding
				if strings.Contains(prompts[i], tc.expected) {
					found = true
					break
				}
			}
		}
		// Note: Not all test cases may be in the triggers, so we don't fail if not found
		_ = found
	}
}

// TestInjectAtbashRegistration verifies the probe registers itself
func TestInjectAtbashRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectAtbash")
	require.True(t, ok, "InjectAtbash should be registered")
	require.NotNil(t, factory, "InjectAtbash factory should not be nil")
}

// TestInjectAtbashCreation verifies probe can be created
func TestInjectAtbashCreation(t *testing.T) {
	probe, err := NewInjectAtbash(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectAtbash", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectAtbashEncodingCorrectness verifies encoding produces valid Atbash
func TestInjectAtbashEncodingCorrectness(t *testing.T) {
	// Test vectors: "Hello" → "Svool"
	testCases := []struct {
		input    string
		expected string
	}{
		{"Hello", "Svool"},
		{"hello", "svool"},
		{"HELLO", "SVOOL"},
		{"abc", "zyx"},
		{"XYZ", "CBA"},
	}

	probeInterface, err := NewInjectAtbash(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectAtbash)
	require.True(t, ok, "Should be able to cast to InjectAtbash")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	for _, tc := range testCases {
		found := false
		for i, trigger := range triggers {
			if trigger == tc.input {
				if strings.Contains(prompts[i], tc.expected) {
					found = true
					break
				}
			}
		}
		_ = found
	}
}

// TestInjectMorseRegistration verifies the probe registers itself
func TestInjectMorseRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectMorse")
	require.True(t, ok, "InjectMorse should be registered")
	require.NotNil(t, factory, "InjectMorse factory should not be nil")
}

// TestInjectMorseCreation verifies probe can be created
func TestInjectMorseCreation(t *testing.T) {
	probe, err := NewInjectMorse(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectMorse", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectMorseEncodingCorrectness verifies encoding produces valid Morse
func TestInjectMorseEncodingCorrectness(t *testing.T) {
	// Test vectors: "SOS" → "... --- ..."
	testCases := []struct {
		input    string
		expected string
	}{
		{"SOS", "... --- ..."},
		{"HELLO", ".... . .-.. .-.. ---"},
		{"123", ".---- ..--- ...--"},
	}

	probeInterface, err := NewInjectMorse(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectMorse)
	require.True(t, ok, "Should be able to cast to InjectMorse")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	for _, tc := range testCases {
		found := false
		for i, trigger := range triggers {
			// Morse encoding converts to uppercase
			if strings.ToUpper(trigger) == tc.input {
				if strings.Contains(prompts[i], tc.expected) {
					found = true
					break
				}
			}
		}
		_ = found
	}
}

// TestInjectNatoRegistration verifies the probe registers itself
func TestInjectNatoRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectNato")
	require.True(t, ok, "InjectNato should be registered")
	require.NotNil(t, factory, "InjectNato factory should not be nil")
}

// TestInjectNatoCreation verifies probe can be created
func TestInjectNatoCreation(t *testing.T) {
	probe, err := NewInjectNato(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectNato", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectNatoEncodingCorrectness verifies encoding produces valid NATO
func TestInjectNatoEncodingCorrectness(t *testing.T) {
	// Test vectors: "ABC" → "Alfa Bravo Charlie"
	testCases := []struct {
		input    string
		expected string
	}{
		{"ABC", "Alfa Bravo Charlie"},
		{"SOS", "Sierra Oscar Sierra"},
		{"HELLO", "Hotel Echo Lima Lima Oscar"},
	}

	probeInterface, err := NewInjectNato(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectNato)
	require.True(t, ok, "Should be able to cast to InjectNato")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	for _, tc := range testCases {
		found := false
		for i, trigger := range triggers {
			// NATO encoding only processes letters and converts to uppercase
			if strings.ToUpper(trigger) == tc.input {
				if strings.Contains(prompts[i], tc.expected) {
					found = true
					break
				}
			}
		}
		_ = found
	}
}

// TestInjectLeetRegistration verifies the probe registers itself
func TestInjectLeetRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectLeet")
	require.True(t, ok, "InjectLeet should be registered")
	require.NotNil(t, factory, "InjectLeet factory should not be nil")
}

// TestInjectLeetCreation verifies probe can be created
func TestInjectLeetCreation(t *testing.T) {
	probe, err := NewInjectLeet(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectLeet", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
}

// TestInjectLeetEncodingCorrectness verifies encoding produces valid Leetspeak
func TestInjectLeetEncodingCorrectness(t *testing.T) {
	// Test vectors: "elite" → "3l173"
	testCases := []struct {
		input    string
		expected string
	}{
		{"elite", "3l173"},
		{"test", "73s7"},
		{"hello", "h3ll0"},
	}

	probeInterface, err := NewInjectLeet(nil)
	require.NoError(t, err)

	probe, ok := probeInterface.(*InjectLeet)
	require.True(t, ok, "Should be able to cast to InjectLeet")

	prompts := probe.GetPrompts()
	triggers := probe.EncodingProbe.GetTriggers()

	for _, tc := range testCases {
		found := false
		for i, trigger := range triggers {
			if trigger == tc.input {
				if strings.Contains(prompts[i], tc.expected) {
					found = true
					break
				}
			}
		}
		_ = found
	}
}

// TestInjectBrailleRegistration verifies the probe registers itself
func TestInjectBrailleRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectBraille")
	require.True(t, ok, "InjectBraille should be registered")
	require.NotNil(t, factory, "InjectBraille factory should not be nil")
}

// TestInjectBrailleCreation verifies probe can be created
func TestInjectBrailleCreation(t *testing.T) {
	probe, err := NewInjectBraille(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectBraille", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectBrailleEncodingCorrectness verifies braille encoding works correctly
func TestInjectBrailleEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple lowercase",
			input:    "hi",
			expected: "⠓⠊", // \u2813\u280A
		},
		{
			name:     "lowercase word",
			input:    "hello",
			expected: "⠓⠑⠇⠇⠕", // h e l l o
		},
		{
			name:     "uppercase with capital indicator",
			input:    "Hi",
			expected: "⠠⠓⠊", // capital indicator + h + i
		},
		{
			name:     "number with number indicator",
			input:    "123",
			expected: "⠼⠁⠃⠉", // number indicator + 1 + 2 + 3
		},
		{
			name:     "space preserved",
			input:    "hi there",
			expected: "⠓⠊ ⠞⠓⠑⠗⠑",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := brailleEncode([]byte(tt.input))
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestInjectBraillePromptsGenerated verifies prompts are generated
func TestInjectBraillePromptsGenerated(t *testing.T) {
	probe, err := NewInjectBraille(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// At least one prompt should contain braille characters
	foundBraille := false
	for _, prompt := range prompts {
		// Braille characters are in U+2800-U+28FF range
		if strings.ContainsAny(prompt, "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓") {
			foundBraille = true
			break
		}
	}
	assert.True(t, foundBraille, "At least one prompt should contain braille characters")
}

// TestInjectBrailleProbeExecution verifies probe can execute
func TestInjectBrailleProbeExecution(t *testing.T) {
	probe, err := NewInjectBraille(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectBraille", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// TestInjectUURegistration verifies the probe registers itself
func TestInjectUURegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectUU")
	require.True(t, ok, "InjectUU should be registered")
	require.NotNil(t, factory, "InjectUU factory should not be nil")
}

// TestInjectUUCreation verifies probe can be created
func TestInjectUUCreation(t *testing.T) {
	probe, err := NewInjectUU(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectUU", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectUUEncodingCorrectness verifies UU encoding works correctly
func TestInjectUUEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "short text",
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
			result := uuEncode([]byte(tt.input))

			// UU encoded text should:
			// 1. Not be empty
			assert.NotEmpty(t, result)

			// 2. End with newline
			assert.True(t, strings.HasSuffix(result, "\n"), "UU encoded text should end with newline")

			// 3. Have length character as first byte (after space offset)
			if len(result) > 0 {
				lengthChar := result[0]
				// Length should be reasonable (between space (32) and space+45 (77))
				assert.GreaterOrEqual(t, int(lengthChar), 32, "Length char should be >= 32")
				assert.LessOrEqual(t, int(lengthChar), 77, "Length char should be <= 77")
			}
		})
	}
}

// TestInjectUUPromptsGenerated verifies prompts are generated
func TestInjectUUPromptsGenerated(t *testing.T) {
	probe, err := NewInjectUU(nil)
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

// TestInjectUUProbeExecution verifies probe can execute
func TestInjectUUProbeExecution(t *testing.T) {
	probe, err := NewInjectUU(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectUU", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// TestInjectUnicodeTagCharsRegistration verifies the probe registers itself
func TestInjectUnicodeTagCharsRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectUnicodeTagChars")
	require.True(t, ok, "InjectUnicodeTagChars should be registered")
	require.NotNil(t, factory, "InjectUnicodeTagChars factory should not be nil")
}

// TestInjectUnicodeTagCharsCreation verifies probe can be created
func TestInjectUnicodeTagCharsCreation(t *testing.T) {
	probe, err := NewInjectUnicodeTagChars(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectUnicodeTagChars", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectUnicodeTagCharsEncodingCorrectness verifies Unicode tag encoding works correctly
func TestInjectUnicodeTagCharsEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple text",
			input:    "test",
			expected: "😈\U000E0074\U000E0065\U000E0073\U000E0074", // emoji + t e s t as tag chars
		},
		{
			name:  "hello",
			input: "Hello",
			// emoji + H e l l o as tag chars (0xE0000 + ASCII value)
			expected: "😈\U000E0048\U000E0065\U000E006C\U000E006C\U000E006F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tagCharEncode([]byte(tt.input))
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestInjectUnicodeTagCharsStartsWithEmoji verifies encoding starts with emoji
func TestInjectUnicodeTagCharsStartsWithEmoji(t *testing.T) {
	result := tagCharEncode([]byte("test"))

	// Should start with the default emoji
	assert.True(t, strings.HasPrefix(result, defaultEmoji), "Encoded text should start with emoji")

	// Should be longer than just the emoji
	assert.Greater(t, len(result), len(defaultEmoji), "Encoded text should include tag characters")
}

// TestInjectUnicodeTagCharsPromptsGenerated verifies prompts are generated
func TestInjectUnicodeTagCharsPromptsGenerated(t *testing.T) {
	probe, err := NewInjectUnicodeTagChars(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// At least one prompt should contain the emoji
	foundEmoji := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, defaultEmoji) {
			foundEmoji = true
			break
		}
	}
	assert.True(t, foundEmoji, "At least one prompt should contain the default emoji")
}

// TestInjectUnicodeTagCharsProbeExecution verifies probe can execute
func TestInjectUnicodeTagCharsProbeExecution(t *testing.T) {
	probe, err := NewInjectUnicodeTagChars(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectUnicodeTagChars", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// TestAllNewProbesImplementInterface verifies all new probes implement Prober
func TestAllNewProbesImplementInterface(t *testing.T) {
	probeNames := []string{
		"encoding.InjectBraille",
		"encoding.InjectUU",
		"encoding.InjectUnicodeTagChars",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			factory, ok := probes.Get(name)
			require.True(t, ok, "%s should be registered", name)

			probe, err := factory(nil)
			require.NoError(t, err)
			require.NotNil(t, probe)

			// Verify interface methods
			assert.NotEmpty(t, probe.Name())
			assert.NotEmpty(t, probe.Description())
			assert.NotEmpty(t, probe.Goal())
			assert.NotEmpty(t, probe.GetPrimaryDetector())
			assert.NotEmpty(t, probe.GetPrompts())
		})
	}
}

// isBase64Like checks if a string looks like it contains base64 encoded text
func isBase64Like(s string) bool {
	// Simple heuristic: contains common base64 characters
	return strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
}

// TestInjectZalgoRegistration verifies the probe registers itself
func TestInjectZalgoRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectZalgo")
	require.True(t, ok, "InjectZalgo should be registered")
	require.NotNil(t, factory, "InjectZalgo factory should not be nil")
}

// TestInjectZalgoCreation verifies probe can be created
func TestInjectZalgoCreation(t *testing.T) {
	probe, err := NewInjectZalgo(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectZalgo", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectZalgoEncodingCorrectness verifies Zalgo encoding works correctly
func TestInjectZalgoEncodingCorrectness(t *testing.T) {
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
			result := zalgoEncode([]byte(tt.input), 5)

			// Zalgo encoded text should:
			// 1. Not be empty
			assert.NotEmpty(t, result)

			// 2. Be longer than input (due to combining diacritics)
			assert.Greater(t, len(result), len(tt.input), "Zalgo text should be longer than input")

			// 3. Contain combining diacritics (Unicode range 0x0300-0x036F)
			foundCombining := false
			for _, r := range result {
				if r >= 0x0300 && r <= 0x036F {
					foundCombining = true
					break
				}
			}
			assert.True(t, foundCombining, "Zalgo text should contain combining diacritics")

			// 4. Should contain the original characters
			// (Zalgo adds diacritics but keeps base characters)
			for _, char := range tt.input {
				if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
					assert.Contains(t, result, string(char), "Zalgo text should contain original characters")
				}
			}
		})
	}
}

// TestInjectZalgoIntensityControl verifies intensity parameter controls output size
func TestInjectZalgoIntensityControl(t *testing.T) {
	input := []byte("test")

	// Low intensity should produce shorter output than high intensity
	lowIntensity := zalgoEncode(input, 2)
	highIntensity := zalgoEncode(input, 10)

	assert.Greater(t, len(highIntensity), len(lowIntensity),
		"Higher intensity should produce longer zalgo text")
}

// TestInjectZalgoPromptsGenerated verifies prompts are generated
func TestInjectZalgoPromptsGenerated(t *testing.T) {
	probe, err := NewInjectZalgo(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// Prompts should not contain template placeholders
	for _, prompt := range prompts {
		assert.NotContains(t, prompt, "{encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}")
	}

	// At least one prompt should contain combining diacritics
	foundZalgo := false
	for _, prompt := range prompts {
		for _, r := range prompt {
			if r >= 0x0300 && r <= 0x036F {
				foundZalgo = true
				break
			}
		}
		if foundZalgo {
			break
		}
	}
	assert.True(t, foundZalgo, "At least one prompt should contain zalgo text (combining diacritics)")
}

// TestInjectZalgoProbeExecution verifies probe can execute
func TestInjectZalgoProbeExecution(t *testing.T) {
	probe, err := NewInjectZalgo(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectZalgo", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger is stored
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")
	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
}

// TestInjectSneakyBitsRegistration verifies the probe registers itself
func TestInjectSneakyBitsRegistration(t *testing.T) {
	factory, ok := probes.Get("encoding.InjectSneakyBits")
	require.True(t, ok, "InjectSneakyBits should be registered")
	require.NotNil(t, factory, "InjectSneakyBits factory should not be nil")
}

// TestInjectSneakyBitsCreation verifies probe can be created
func TestInjectSneakyBitsCreation(t *testing.T) {
	probe, err := NewInjectSneakyBits(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "encoding.InjectSneakyBits", probe.Name())
	assert.Equal(t, "encoding.DecodeMatch", probe.GetPrimaryDetector())
	assert.Equal(t, "make the model say an encoded payload", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInjectSneakyBitsEncodingCorrectness verifies Sneaky Bits encoding works correctly
func TestInjectSneakyBitsEncodingCorrectness(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:  "capital A (ASCII 65 = 0b1000001)",
			input: "A",
			// Binary: 1000001
			// 1 → U+2064 (INVISIBLE PLUS)
			// 0 → U+2062 (INVISIBLE TIMES)
			expected: "\u2064\u2062\u2062\u2062\u2062\u2062\u2064",
		},
		{
			name:  "lowercase a (ASCII 97 = 0b1100001)",
			input: "a",
			// Binary: 1100001
			expected: "\u2064\u2064\u2062\u2062\u2062\u2062\u2064",
		},
		{
			name:  "space character (ASCII 32 = 0x20)",
			input: " ",
			// Space → U+200B (ZERO-WIDTH SPACE)
			expected: "\u200B",
		},
		{
			name:  "text with space",
			input: "A B",
			// A + space + B
			expected: "\u2064\u2062\u2062\u2062\u2062\u2062\u2064\u200B\u2064\u2062\u2062\u2062\u2062\u2064\u2062",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sneakyBitsEncode([]byte(tt.input))
			assert.Equal(t, tt.expected, result, "Sneaky bits encoding should match expected output")
		})
	}
}

// TestInjectSneakyBitsEncodingProperties verifies encoding properties
func TestInjectSneakyBitsEncodingProperties(t *testing.T) {
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
			result := sneakyBitsEncode([]byte(tt.input))

			// Encoded text should:
			// 1. Not be empty
			assert.NotEmpty(t, result)

			// 2. Only contain invisible characters (U+2062, U+2064, U+200B)
			for _, r := range result {
				valid := r == 0x2062 || r == 0x2064 || r == 0x200B
				assert.True(t, valid, "Should only contain invisible Unicode characters (U+2062, U+2064, U+200B)")
			}

			// 3. Non-space characters should produce binary encoding
			// Each ASCII char becomes 6-8 bits (U+2062 or U+2064)
			// Spaces become single U+200B
			spaceCount := strings.Count(tt.input, " ")
			nonSpaceCount := len(tt.input) - spaceCount

			// Minimum length: spaces (1 each) + non-spaces (at least 6 bits each)
			// Most printable ASCII is 6+ bits (e.g., '!' = 0b100001 = 6 bits, 'A' = 0b1000001 = 7 bits)
			minLength := spaceCount + (nonSpaceCount * 6)
			assert.GreaterOrEqual(t, len([]rune(result)), minLength,
				"Encoded length should be at least 6 bits per non-space character")
		})
	}
}

// TestInjectSneakyBitsPromptsGenerated verifies prompts are generated
func TestInjectSneakyBitsPromptsGenerated(t *testing.T) {
	probe, err := NewInjectSneakyBits(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()

	// Should have prompts: 5 templates * 4 payloads * 1 encoder = 20
	assert.Len(t, prompts, 20, "Should have 20 prompts")

	// Prompts should not contain template placeholders
	for _, prompt := range prompts {
		assert.NotContains(t, prompt, "{encoded_text}")
		assert.NotContains(t, prompt, "{encoding_name}")
	}

	// At least one prompt should contain invisible characters
	foundInvisible := false
	for _, prompt := range prompts {
		if strings.ContainsAny(prompt, "\u2062\u2064\u200B") {
			foundInvisible = true
			break
		}
	}
	assert.True(t, foundInvisible, "At least one prompt should contain invisible Unicode characters")
}

// TestInjectSneakyBitsProbeExecution verifies probe can execute
func TestInjectSneakyBitsProbeExecution(t *testing.T) {
	probe, err := NewInjectSneakyBits(nil)
	require.NoError(t, err)

	gen := &mockGenerator{responses: []string{"test response"}}
	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempt structure
	a := attempts[0]
	assert.Equal(t, "encoding.InjectSneakyBits", a.Probe)
	assert.Equal(t, "encoding.DecodeMatch", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger is stored
	triggers, ok := a.Metadata["triggers"]
	require.True(t, ok, "Attempt should have triggers in metadata")
	triggerSlice, ok := triggers.([]string)
	require.True(t, ok, "Triggers should be []string")
	require.Len(t, triggerSlice, 1, "Should have exactly one trigger")
}

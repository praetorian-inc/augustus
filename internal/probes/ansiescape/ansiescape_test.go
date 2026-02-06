package ansiescape

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnsiEscaped_Registration(t *testing.T) {
	// Test that AnsiEscaped probe can be created via registry
	factory, ok := probes.Get("ansiescape.AnsiEscaped")
	require.True(t, ok, "ansiescape.AnsiEscaped should be registered")

	probe, err := factory(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)
}

func TestAnsiEscaped_ImplementsProber(t *testing.T) {
	// Verify AnsiEscaped implements Prober interface
	var _ probes.Prober = &AnsiEscaped{}
}

func TestAnsiEscaped_Metadata(t *testing.T) {
	p, err := NewAnsiEscaped(nil)
	require.NoError(t, err)
	probe := p.(*AnsiEscaped)

	// Test Name
	assert.Equal(t, "ansiescape.AnsiEscaped", probe.Name())

	// Test Description
	desc := probe.Description()
	assert.Contains(t, desc, "ANSI")
	assert.Contains(t, desc, "escaped")

	// Test Goal
	goal := probe.Goal()
	assert.Contains(t, goal, "escaped ANSI")

	// Test PrimaryDetector
	detector := probe.GetPrimaryDetector()
	assert.Equal(t, "ansiescape.Escaped", detector)
}

func TestAnsiEscaped_GeneratesPrompts(t *testing.T) {
	p, err := NewAnsiEscaped(nil)
	require.NoError(t, err)
	probe := p.(*AnsiEscaped)

	prompts := probe.GetPrompts()

	// Should generate prompts from templates
	assert.NotEmpty(t, prompts, "AnsiEscaped should generate prompts")

	// Check that prompts contain expected patterns
	foundAsk := false
	foundRepeat := false

	for _, p := range prompts {
		if containsAny(p, []string{"What's terminal ANSI", "What's VT100", "What OSC 8"}) {
			foundAsk = true
		}
		if containsAny(p, []string{"repeat", "Print the following", "Output everything after"}) {
			foundRepeat = true
		}
	}

	assert.True(t, foundAsk, "Should have prompts asking about ANSI codes")
	assert.True(t, foundRepeat, "Should have prompts asking to repeat ANSI codes")
}

func TestAnsiEscaped_ProbeExecution(t *testing.T) {
	p, err := NewAnsiEscaped(nil)
	require.NoError(t, err)
	probe := p.(*AnsiEscaped)

	mockGen := testutil.NewMockGenerator("\\x1b[32m")

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, mockGen)

	require.NoError(t, err)
	assert.NotEmpty(t, attempts)

	// Verify each attempt has required fields
	for _, a := range attempts {
		assert.Equal(t, "ansiescape.AnsiEscaped", a.Probe)
		assert.Equal(t, "ansiescape.Escaped", a.Detector)
		assert.NotEmpty(t, a.Prompt)
		assert.NotEmpty(t, a.Outputs)
	}
}

func TestAnsiRaw_Registration(t *testing.T) {
	// Test that AnsiRaw probe can be created via registry
	factory, ok := probes.Get("ansiescape.AnsiRaw")
	require.True(t, ok, "ansiescape.AnsiRaw should be registered")

	probe, err := factory(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)
}

func TestAnsiRaw_ImplementsProber(t *testing.T) {
	// Verify AnsiRaw implements Prober interface
	var _ probes.Prober = &AnsiRaw{}
}

func TestAnsiRaw_Metadata(t *testing.T) {
	p, err := NewAnsiRaw(nil)
	require.NoError(t, err)
	probe := p.(*AnsiRaw)

	// Test Name
	assert.Equal(t, "ansiescape.AnsiRaw", probe.Name())

	// Test Description
	desc := probe.Description()
	assert.Contains(t, desc, "ANSI")
	assert.Contains(t, desc, "raw")

	// Test Goal
	goal := probe.Goal()
	assert.Contains(t, goal, "raw ANSI")

	// Test PrimaryDetector
	detector := probe.GetPrimaryDetector()
	assert.Equal(t, "ansiescape.Raw", detector)
}

func TestAnsiRaw_GeneratesPrompts(t *testing.T) {
	p, err := NewAnsiRaw(nil)
	require.NoError(t, err)
	probe := p.(*AnsiRaw)

	prompts := probe.GetPrompts()

	// Should generate prompts from templates
	assert.NotEmpty(t, prompts, "AnsiRaw should generate prompts")

	// AnsiRaw should have more prompts than AnsiEscaped
	// (includes unescape stubs)
	ep, err := NewAnsiEscaped(nil)
	require.NoError(t, err)
	escapedProbe := ep.(*AnsiEscaped)
	assert.Greater(t, len(prompts), len(escapedProbe.GetPrompts()))
}

func TestAnsiRaw_ProbeExecution(t *testing.T) {
	p, err := NewAnsiRaw(nil)
	require.NoError(t, err)
	probe := p.(*AnsiRaw)

	mockGen := testutil.NewMockGenerator("\x1b[32m")

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, mockGen)

	require.NoError(t, err)
	assert.NotEmpty(t, attempts)

	// Verify each attempt has required fields
	for _, a := range attempts {
		assert.Equal(t, "ansiescape.AnsiRaw", a.Probe)
		assert.Equal(t, "ansiescape.Raw", a.Detector)
		assert.NotEmpty(t, a.Prompt)
		assert.NotEmpty(t, a.Outputs)
	}
}

func TestPayloads_Existence(t *testing.T) {
	// Test that payload constants are defined
	assert.NotEmpty(t, livePayloadTokens, "livePayloadTokens should be defined")
	assert.NotEmpty(t, livePayloads, "livePayloads should be defined")
	assert.NotEmpty(t, escapedPayloads, "escapedPayloads should be defined")
	assert.NotEmpty(t, escapedSeqs, "escapedSeqs should be defined")
	assert.NotEmpty(t, escapedCommands, "escapedCommands should be defined")
	assert.NotEmpty(t, rawSeqs, "rawSeqs should be defined")
	assert.NotEmpty(t, rawCommands, "rawCommands should be defined")
}

func TestPayloads_RawContent(t *testing.T) {
	// Verify raw payloads contain actual escape bytes or C1 control codes
	for _, payload := range livePayloadTokens {
		// Should contain either ESC byte (\x1b) or C1 control codes (\x9b, \x9d)
		hasEscape := containsAny(payload, []string{"\x1b", "\x9b", "\x9d"})
		assert.True(t, hasEscape, "Live payload should contain escape byte or C1 control code: %q", payload)
	}
}

func TestPayloads_EscapedContent(t *testing.T) {
	// Verify escaped payloads are string representations
	for _, payload := range escapedPayloads {
		// Should contain escaped representations like \x1b, \033, or be C1 codes like \x9b
		hasEscaped := containsAny(payload, []string{`\x1b`, `\033`, `\u001b`, `\27`, `\e`, `\x9b`, `\x9d`})
		assert.True(t, hasEscaped, "Escaped payload should contain escaped representation: %s", payload)
	}
}

// Helper function to check if string contains any of the substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) && contains(s, substr) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

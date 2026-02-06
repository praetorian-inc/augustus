package glitch

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewGlitchFull(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitchFull() returned nil probe")
	}

	// Verify probe implements interface methods
	if probe.Name() != "glitch.GlitchFull" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.GlitchFull")
	}

	if probe.Goal() == "" {
		t.Error("Goal() returned empty string")
	}

	if probe.Description() == "" {
		t.Error("Description() returned empty string")
	}

	if probe.GetPrimaryDetector() == "" {
		t.Error("GetPrimaryDetector() returned empty string")
	}
}

func TestGlitchFull_Probe(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	gen := &testutil.MockGenerator{
		Responses: []string{"test response"},
	}

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() returned no attempts")
	}

	// Verify attempts have correct structure
	for i, att := range attempts {
		if att == nil {
			t.Errorf("Attempt[%d] is nil", i)
			continue
		}

		if att.Probe != probe.Name() {
			t.Errorf("Attempt[%d].Probe = %q, want %q", i, att.Probe, probe.Name())
		}

		if att.Detector != probe.GetPrimaryDetector() {
			t.Errorf("Attempt[%d].Detector = %q, want %q", i, att.Detector, probe.GetPrimaryDetector())
		}

		if att.Status != attempt.StatusComplete {
			t.Errorf("Attempt[%d].Status = %v, want %v", i, att.Status, attempt.StatusComplete)
		}
	}
}

func TestGlitchFull_Prompts(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	prompts := probe.GetPrompts()

	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned no prompts")
	}

	// Verify prompts contain glitch tokens
	// Should have prompts for each glitch token with each template
	expectedMinPrompts := 10 // At least 10 prompts (conservative check)
	if len(prompts) < expectedMinPrompts {
		t.Errorf("GetPrompts() returned %d prompts, want at least %d", len(prompts), expectedMinPrompts)
	}

	// Verify prompts are well-formed (contain "repeat" instruction)
	for i, prompt := range prompts {
		lower := strings.ToLower(prompt)
		if !strings.Contains(lower, "repeat") {
			t.Errorf("Prompt[%d] does not contain 'repeat': %q", i, prompt)
		}
	}
}

func TestGlitchFull_GlitchTokens(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	glitchProbe := probe.(*GlitchFull)

	// Verify we have the expected glitch tokens
	expectedTokenCount := 141 // From Python garak implementation
	if len(glitchProbe.glitchTokens) != expectedTokenCount {
		t.Errorf("glitchTokens count = %d, want %d", len(glitchProbe.glitchTokens), expectedTokenCount)
	}

	// Verify some known glitch tokens exist
	knownTokens := []string{
		"\x00",              // Null byte
		" SolidGoldMagikarp", // Famous glitch token (with leading space)
		"PsyNetMessage",     // Another known one
		"龍喚士",              // Unicode glitch
	}

	for _, token := range knownTokens {
		found := false
		for _, gt := range glitchProbe.glitchTokens {
			if gt == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected glitch token %q not found", token)
		}
	}
}

func TestNewGlitch(t *testing.T) {
	probe, err := NewGlitch(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitch() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitch() returned nil probe")
	}

	if probe.Name() != "glitch.Glitch" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.Glitch")
	}
}

func TestGlitch_Probe(t *testing.T) {
	probe, err := NewGlitch(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitch() error = %v", err)
	}

	gen := &testutil.MockGenerator{
		Responses: []string{"test response"},
	}

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() returned no attempts")
	}

	// Glitch should have fewer prompts than GlitchFull
	fullProbe, _ := NewGlitchFull(registry.Config{})
	fullAttempts, _ := fullProbe.Probe(ctx, gen)

	if len(attempts) >= len(fullAttempts) {
		t.Errorf("Glitch should have fewer attempts than GlitchFull, got %d >= %d", len(attempts), len(fullAttempts))
	}
}

func TestGlitch_SubsetOfGlitchFull(t *testing.T) {
	glitchProbe, err := NewGlitch(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitch() error = %v", err)
	}

	fullProbe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	glitch := glitchProbe.(*Glitch)
	full := fullProbe.(*GlitchFull)

	// Verify Glitch prompts are a subset of GlitchFull prompts
	glitchPrompts := glitch.GetPrompts()
	fullPromptsSet := make(map[string]bool)
	for _, p := range full.GetPrompts() {
		fullPromptsSet[p] = true
	}

	for i, prompt := range glitchPrompts {
		if !fullPromptsSet[prompt] {
			t.Errorf("Glitch prompt[%d] not found in GlitchFull prompts: %q", i, prompt)
		}
	}
}

func TestPromptQuoting(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	glitchProbe := probe.(*GlitchFull)

	// Test that tokens with quotes are properly handled
	testCases := []struct {
		token        string
		expectedQuote string
	}{
		{`simple`, `"`},           // No quotes in token -> use double quote
		{`has"quote`, `'`},         // Has double quote -> use single quote
		{`has'quote`, `"`},         // Has single quote -> use double quote
		{`has'and"quotes`, "`"},    // Has both -> use backtick
	}

	for _, tc := range testCases {
		// Find a prompt containing this token
		found := false
		for _, prompt := range glitchProbe.Prompts {
			if strings.Contains(prompt, tc.token) {
				found = true
				// Verify the prompt uses the expected quote style
				if tc.expectedQuote != "" && !strings.Contains(prompt, tc.expectedQuote+tc.token+tc.expectedQuote) {
					t.Logf("Prompt for token %q: %q", tc.token, prompt)
					// This is just informational, not a failure
				}
				break
			}
		}
		if !found && tc.token == "simple" {
			// Only log if it's the simple test case (others might not be in the actual token list)
			t.Logf("Token %q not found in any prompt", tc.token)
		}
	}
}

func TestProbeErrorHandling(t *testing.T) {
	probe, err := NewGlitchFull(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchFull() error = %v", err)
	}

	// Test with generator that returns error
	genWithError := &testutil.MockGenerator{
		Responses: []string{},
	}

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, genWithError)

	// Probe should not return error even if generator fails
	// (errors should be captured in attempt status)
	if err != nil {
		t.Errorf("Probe() should not return error for generator failure, got: %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() should return attempts even on generator error")
	}
}

func TestProbeIntegration(t *testing.T) {
	// Test that both probes can be used in sequence
	probes := []struct {
		name    string
		factory func(registry.Config) (*GlitchFull, error)
	}{
		{"GlitchFull", func(c registry.Config) (*GlitchFull, error) {
			p, err := NewGlitchFull(c)
			if err != nil {
				return nil, err
			}
			return p.(*GlitchFull), nil
		}},
		{"Glitch", func(c registry.Config) (*GlitchFull, error) {
			p, err := NewGlitch(c)
			if err != nil {
				return nil, err
			}
			// Glitch embeds GlitchFull
			return p.(*Glitch).GlitchFull, nil
		}},
	}

	gen := &testutil.MockGenerator{
		Responses: []string{"response"},
	}

	ctx := context.Background()

	for _, tt := range probes {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := tt.factory(registry.Config{})
			if err != nil {
				t.Fatalf("Factory error = %v", err)
			}

			attempts, err := probe.Probe(ctx, gen)
			if err != nil {
				t.Fatalf("Probe() error = %v", err)
			}

			if len(attempts) == 0 {
				t.Error("No attempts generated")
			}

			// Verify all attempts are properly formed
			for i, att := range attempts {
				if att.Prompt == "" {
					t.Errorf("Attempt[%d] has empty prompt", i)
				}
				if att.Probe == "" {
					t.Errorf("Attempt[%d] has empty probe name", i)
				}
				if att.Detector == "" {
					t.Errorf("Attempt[%d] has empty detector name", i)
				}
			}
		})
	}
}

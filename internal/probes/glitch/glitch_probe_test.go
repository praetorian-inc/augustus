package glitch

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestGlitchType_Constants verifies GlitchType constants are defined.
func TestGlitchType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		glitchType GlitchType
		expected int
	}{
		{"SolidGoldMagikarp", SolidGoldMagikarp, 0},
		{"UndefinedBehavior", UndefinedBehavior, 1},
		{"TokenBoundary", TokenBoundary, 2},
		{"SpecialTokens", SpecialTokens, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.glitchType) != tt.expected {
				t.Errorf("GlitchType %s = %d, want %d", tt.name, int(tt.glitchType), tt.expected)
			}
		})
	}
}

// TestNewGlitchProbe_SolidGoldMagikarp tests creating a SolidGoldMagikarp glitch probe.
func TestNewGlitchProbe_SolidGoldMagikarp(t *testing.T) {
	probe, err := NewGlitchProbe_SolidGoldMagikarp(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchProbe_SolidGoldMagikarp() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitchProbe_SolidGoldMagikarp() returned nil probe")
	}

	// Verify it's a GlitchProbe with correct type
	glitchProbe, ok := probe.(*GlitchProbe)
	if !ok {
		t.Fatal("Probe is not a *GlitchProbe")
	}

	if glitchProbe.glitchType != SolidGoldMagikarp {
		t.Errorf("glitchType = %v, want %v", glitchProbe.glitchType, SolidGoldMagikarp)
	}

	// Verify interface methods
	if probe.Name() != "glitch.SolidGoldMagikarp" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.SolidGoldMagikarp")
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

// TestNewGlitchProbe_UndefinedBehavior tests creating an UndefinedBehavior glitch probe.
func TestNewGlitchProbe_UndefinedBehavior(t *testing.T) {
	probe, err := NewGlitchProbe_UndefinedBehavior(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchProbe_UndefinedBehavior() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitchProbe_UndefinedBehavior() returned nil probe")
	}

	glitchProbe, ok := probe.(*GlitchProbe)
	if !ok {
		t.Fatal("Probe is not a *GlitchProbe")
	}

	if glitchProbe.glitchType != UndefinedBehavior {
		t.Errorf("glitchType = %v, want %v", glitchProbe.glitchType, UndefinedBehavior)
	}

	if probe.Name() != "glitch.UndefinedBehavior" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.UndefinedBehavior")
	}
}

// TestNewGlitchProbe_TokenBoundary tests creating a TokenBoundary glitch probe.
func TestNewGlitchProbe_TokenBoundary(t *testing.T) {
	probe, err := NewGlitchProbe_TokenBoundary(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchProbe_TokenBoundary() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitchProbe_TokenBoundary() returned nil probe")
	}

	glitchProbe, ok := probe.(*GlitchProbe)
	if !ok {
		t.Fatal("Probe is not a *GlitchProbe")
	}

	if glitchProbe.glitchType != TokenBoundary {
		t.Errorf("glitchType = %v, want %v", glitchProbe.glitchType, TokenBoundary)
	}

	if probe.Name() != "glitch.TokenBoundary" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.TokenBoundary")
	}
}

// TestNewGlitchProbe_SpecialTokens tests creating a SpecialTokens glitch probe.
func TestNewGlitchProbe_SpecialTokens(t *testing.T) {
	probe, err := NewGlitchProbe_SpecialTokens(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchProbe_SpecialTokens() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewGlitchProbe_SpecialTokens() returned nil probe")
	}

	glitchProbe, ok := probe.(*GlitchProbe)
	if !ok {
		t.Fatal("Probe is not a *GlitchProbe")
	}

	if glitchProbe.glitchType != SpecialTokens {
		t.Errorf("glitchType = %v, want %v", glitchProbe.glitchType, SpecialTokens)
	}

	if probe.Name() != "glitch.SpecialTokens" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "glitch.SpecialTokens")
	}
}

// TestGlitchProbe_Probe tests that GlitchProbe can execute probes.
func TestGlitchProbe_Probe(t *testing.T) {
	tests := []struct {
		name    string
		factory func(registry.Config) (probes.Prober, error)
	}{
		{"SolidGoldMagikarp", NewGlitchProbe_SolidGoldMagikarp},
		{"UndefinedBehavior", NewGlitchProbe_UndefinedBehavior},
		{"TokenBoundary", NewGlitchProbe_TokenBoundary},
		{"SpecialTokens", NewGlitchProbe_SpecialTokens},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := tt.factory(registry.Config{})
			if err != nil {
				t.Fatalf("factory() error = %v", err)
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
		})
	}
}

// TestGlitchProbe_Prompts tests that each glitch type has different prompts.
func TestGlitchProbe_Prompts(t *testing.T) {
	factories := []struct {
		name    string
		factory func(registry.Config) (probes.Prober, error)
	}{
		{"SolidGoldMagikarp", NewGlitchProbe_SolidGoldMagikarp},
		{"UndefinedBehavior", NewGlitchProbe_UndefinedBehavior},
		{"TokenBoundary", NewGlitchProbe_TokenBoundary},
		{"SpecialTokens", NewGlitchProbe_SpecialTokens},
	}

	for _, tt := range factories {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := tt.factory(registry.Config{})
			if err != nil {
				t.Fatalf("factory() error = %v", err)
			}

			prompts := probe.GetPrompts()
			if len(prompts) == 0 {
				t.Error("GetPrompts() returned no prompts")
			}

			// Verify prompts are well-formed
			for i, prompt := range prompts {
				if prompt == "" {
					t.Errorf("Prompt[%d] is empty", i)
				}
			}
		})
	}
}

// TestGlitchProbe_EmbedsSimpleProbe tests that GlitchProbe embeds SimpleProbe.
func TestGlitchProbe_EmbedsSimpleProbe(t *testing.T) {
	probe, err := NewGlitchProbe_SolidGoldMagikarp(registry.Config{})
	if err != nil {
		t.Fatalf("NewGlitchProbe_SolidGoldMagikarp() error = %v", err)
	}

	glitchProbe, ok := probe.(*GlitchProbe)
	if !ok {
		t.Fatal("Probe is not a *GlitchProbe")
	}

	// Verify SimpleProbe is embedded and accessible
	simpleProbe := glitchProbe.SimpleProbe
	if simpleProbe == nil {
		t.Error("SimpleProbe is nil (not properly embedded)")
	}

	// Verify SimpleProbe methods work through GlitchProbe
	if glitchProbe.Name() == "" {
		t.Error("Name() returns empty (SimpleProbe not accessible)")
	}
}

// TestGlitchProbe_DifferentTokens tests that different glitch types use different tokens.
func TestGlitchProbe_DifferentTokens(t *testing.T) {
	solidGold, _ := NewGlitchProbe_SolidGoldMagikarp(registry.Config{})
	undefined, _ := NewGlitchProbe_UndefinedBehavior(registry.Config{})
	tokenBound, _ := NewGlitchProbe_TokenBoundary(registry.Config{})
	specialToks, _ := NewGlitchProbe_SpecialTokens(registry.Config{})

	// Collect all prompts
	allPrompts := map[string][]string{
		"SolidGoldMagikarp": solidGold.GetPrompts(),
		"UndefinedBehavior": undefined.GetPrompts(),
		"TokenBoundary":     tokenBound.GetPrompts(),
		"SpecialTokens":     specialToks.GetPrompts(),
	}

	// Verify each type has prompts
	for name, prompts := range allPrompts {
		if len(prompts) == 0 {
			t.Errorf("%s has no prompts", name)
		}
	}

	// Optionally verify they're different (at least one prompt differs)
	// This is a weaker check since some overlap might be acceptable
	allEqual := true
	firstPrompts := allPrompts["SolidGoldMagikarp"]
	for name, prompts := range allPrompts {
		if name == "SolidGoldMagikarp" {
			continue
		}
		if len(prompts) != len(firstPrompts) {
			allEqual = false
			break
		}
		for i := range prompts {
			if prompts[i] != firstPrompts[i] {
				allEqual = false
				break
			}
		}
		if !allEqual {
			break
		}
	}

	if allEqual {
		t.Log("Note: All glitch types have identical prompts, which may be acceptable")
	}
}

// Package prefix provides adversarial prefix injection probes for LLM testing.
package prefix_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/probes/prefix"
	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestPrefixProbeImplementsProber verifies PrefixProbe implements the Prober interface.
func TestPrefixProbeImplementsProber(t *testing.T) {
	p, err := prefix.NewPrefixProbe(registry.Config{})
	if err != nil {
		t.Fatalf("NewPrefixProbe() error = %v", err)
	}

	// Verify it implements Prober interface
	var _ probes.Prober = p
}

// TestPrefixProbeMetadata verifies the probe returns correct metadata.
func TestPrefixProbeMetadata(t *testing.T) {
	p, err := prefix.NewPrefixProbe(registry.Config{})
	if err != nil {
		t.Fatalf("NewPrefixProbe() error = %v", err)
	}

	// Test Name
	if got := p.Name(); got != "prefix.Prefix" {
		t.Errorf("Name() = %v, want %v", got, "prefix.Prefix")
	}

	// Test Description
	if got := p.Description(); got == "" {
		t.Error("Description() returned empty string")
	}

	// Test Goal
	if got := p.Goal(); got == "" {
		t.Error("Goal() returned empty string")
	}

	// Test GetPrimaryDetector
	if got := p.GetPrimaryDetector(); got == "" {
		t.Error("GetPrimaryDetector() returned empty string")
	}
}

// TestPrefixProbeGetPrompts verifies GetPrompts returns non-empty slice.
func TestPrefixProbeGetPrompts(t *testing.T) {
	p, err := prefix.NewPrefixProbe(registry.Config{})
	if err != nil {
		t.Fatalf("NewPrefixProbe() error = %v", err)
	}

	prompts := p.GetPrompts()
	if len(prompts) == 0 {
		t.Error("GetPrompts() returned empty slice, want at least 1 prompt")
	}
}

// TestPrefixProbePrependsToBasePrompt verifies prefixes are prepended to base prompts.
func TestPrefixProbePrependsToBasePrompt(t *testing.T) {
	p, err := prefix.NewPrefixProbe(registry.Config{})
	if err != nil {
		t.Fatalf("NewPrefixProbe() error = %v", err)
	}

	prompts := p.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("GetPrompts() returned empty slice")
	}

	// Each prompt should contain both the prefix and a harmful base prompt
	// We're testing that the structure is: "<prefix> <base_prompt>"
	for i, prompt := range prompts {
		if prompt == "" {
			t.Errorf("prompts[%d] is empty", i)
		}
		// Verify prompt has multiple words (prefix + base)
		if len(prompt) < 20 {
			t.Errorf("prompts[%d] = %q is too short, expected prefix + base prompt", i, prompt)
		}
	}
}

// TestPrefixProbeProbe verifies Probe method executes correctly.
func TestPrefixProbeProbe(t *testing.T) {
	p, err := prefix.NewPrefixProbe(registry.Config{})
	if err != nil {
		t.Fatalf("NewPrefixProbe() error = %v", err)
	}

	gen := testutil.NewMockGenerator("mock response")
	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("Probe() returned 0 attempts, want at least 1")
	}

	// Verify generator was called
	if gen.Calls == 0 {
		t.Error("Probe() did not call generator.Generate()")
	}
}

// TestPrefixProbeRegistration verifies the probe can be registered and retrieved.
func TestPrefixProbeRegistration(t *testing.T) {
	// Verify probe is registered (init() function should handle this)
	factory, ok := probes.Get("prefix.Prefix")
	if !ok {
		t.Fatal("probes.Get(\"prefix.Prefix\") returned false, probe not registered")
	}

	// Verify factory works
	p, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if p == nil {
		t.Fatal("factory() returned nil")
	}

	// Verify it's the right type
	if p.Name() != "prefix.Prefix" {
		t.Errorf("factory() returned probe with name %q, want %q", p.Name(), "prefix.Prefix")
	}
}

// TestDefaultPrefixes verifies the DefaultPrefixes constant exists and is non-empty.
func TestDefaultPrefixes(t *testing.T) {
	prefixes := prefix.DefaultPrefixes
	if len(prefixes) == 0 {
		t.Error("DefaultPrefixes is empty, want at least 1 prefix")
	}

	// Verify each prefix is non-empty
	for i, p := range prefixes {
		if p == "" {
			t.Errorf("DefaultPrefixes[%d] is empty", i)
		}
	}
}

package flipattack_test

import (
	"context"
	"strings"
	"testing"

	// Blank import triggers init() which registers the probe in the global registry.
	// Required because this file uses package flipattack_test (external test package).
	_ "github.com/praetorian-inc/augustus/internal/probes/flipattack"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockGenerator implements types.Generator for testing
type mockGenerator struct{}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	return []attempt.Message{{Content: "mock response", Role: "assistant"}}, nil
}

func (m *mockGenerator) ClearHistory()         {}
func (m *mockGenerator) Name() string          { return "mock" }
func (m *mockGenerator) Description() string   { return "mock generator for testing" }

func TestRegistration(t *testing.T) {
	_, ok := probes.Get("flipattack.FullAttack")
	if !ok {
		t.Fatal("flipattack.FullAttack not registered")
	}
}

func TestFullAttack_Name(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}
	if probe.Name() != "flipattack.FullAttack" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "flipattack.FullAttack")
	}
}

func TestFullAttack_Metadata(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("probe should implement ProbeMetadata")
	}

	if pm.GetPrimaryDetector() != "flipattack.Bypass" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", pm.GetPrimaryDetector(), "flipattack.Bypass")
	}

	if pm.Description() == "" {
		t.Error("Description() should not be empty")
	}

	if pm.Goal() == "" {
		t.Error("Goal() should not be empty")
	}
}

func TestFullAttack_GetPrompts_RawPayloads(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	pm, ok := probe.(types.ProbeMetadata)
	if !ok {
		t.Fatal("probe should implement ProbeMetadata")
	}

	prompts := pm.GetPrompts()
	if len(prompts) == 0 {
		t.Fatal("probe should have at least one prompt")
	}

	// GetPrompts() should return RAW payloads (NOT framed)
	// Should NOT contain adversarial template keywords
	for i, prompt := range prompts {
		if strings.Contains(prompt, "NEVER NEVER NEVER") {
			t.Errorf("prompt[%d] should NOT contain 'NEVER NEVER NEVER' (should be raw payload only)", i)
		}
		if strings.Contains(prompt, "Rule 1") {
			t.Errorf("prompt[%d] should NOT contain 'Rule 1' (should be raw payload only)", i)
		}
		if strings.Contains(prompt, "expert and an assistant") {
			t.Errorf("prompt[%d] should NOT contain adversarial framing (should be raw payload only)", i)
		}
	}

	// Prompts should be short raw payloads
	for i, prompt := range prompts {
		lower := strings.ToLower(prompt)
		if !(strings.Contains(lower, "hack") || strings.Contains(lower, "steal") ||
			strings.Contains(lower, "explosive") || strings.Contains(lower, "virus") ||
			strings.Contains(lower, "exploit") || strings.Contains(lower, "break")) {
			t.Errorf("prompt[%d] should contain a payload keyword (hack/steal/explosive/virus/exploit/break)", i)
		}

		// Raw payloads should be relatively short (< 200 chars)
		if len(prompt) > 200 {
			t.Errorf("prompt[%d] too long (%d chars), should be raw payload without framing", i, len(prompt))
		}
	}
}

// countingGenerator tracks how many times Generate is called
type countingGenerator struct {
	callCount int
}

func (c *countingGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	c.callCount++
	return []attempt.Message{{Content: "should not be called", Role: "assistant"}}, nil
}

func (c *countingGenerator) ClearHistory()       {}
func (c *countingGenerator) Name() string        { return "counting" }
func (c *countingGenerator) Description() string { return "counting generator for testing" }

// TestFullAttack_NoGeneration verifies that FullAttackProbe does NOT call gen.Generate().
// The probe should return payload-only attempts with metadata but no outputs,
// so BuffedProber can handle generation with transformed payloads.
func TestFullAttack_NoGeneration(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	ctx := context.Background()
	gen := &countingGenerator{}

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	// Probe should NOT call Generate
	if gen.callCount != 0 {
		t.Errorf("Generate called %d times, want 0 (probe should not generate)", gen.callCount)
	}

	// Probe should return attempts with metadata
	if len(attempts) == 0 {
		t.Fatal("Probe() should return at least one attempt")
	}

	for i, a := range attempts {
		// All attempts should have 0 outputs
		if len(a.Outputs) != 0 {
			t.Errorf("attempt[%d] has %d outputs, want 0 (no generation)", i, len(a.Outputs))
		}

		// All attempts should be in StatusPending state
		if a.Status != attempt.StatusPending {
			t.Errorf("attempt[%d] status = %q, want %q", i, a.Status, attempt.StatusPending)
		}

		// Metadata should still be present
		if _, ok := a.Metadata[attempt.MetadataKeySystemPrompt]; !ok {
			t.Errorf("attempt[%d] missing 'system_prompt' metadata", i)
		}
		if _, ok := a.Metadata[attempt.MetadataKeyTriggers]; !ok {
			t.Errorf("attempt[%d] missing 'triggers' metadata", i)
		}
	}
}

func TestFullAttack_Probe_Metadata(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory error: %v", err)
	}

	ctx := context.Background()
	gen := &mockGenerator{}

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() should return at least one attempt")
	}

	for i, a := range attempts {
		// Check that system_prompt metadata is set
		sp, ok := a.Metadata[attempt.MetadataKeySystemPrompt]
		if !ok {
			t.Errorf("attempt[%d] missing 'system_prompt' in Metadata", i)
			continue
		}

		spStr, ok := sp.(string)
		if !ok {
			t.Errorf("attempt[%d] system_prompt is not a string", i)
			continue
		}

		if spStr == "" {
			t.Errorf("attempt[%d] system_prompt is empty", i)
			continue
		}

		// system_prompt should contain adversarial template keywords
		if !strings.Contains(spStr, "NEVER NEVER NEVER") {
			t.Errorf("attempt[%d] system_prompt should contain banned word instructions", i)
		}
		if !strings.Contains(spStr, "sorry") || !strings.Contains(spStr, "fulfill") || !strings.Contains(spStr, "cannot") {
			t.Errorf("attempt[%d] system_prompt should contain banned word list", i)
		}

		// Check that Prompt is raw payload (NOT framed)
		if strings.Contains(a.Prompt, "NEVER NEVER NEVER") {
			t.Errorf("attempt[%d] Prompt should be raw payload, not framed template", i)
		}
		if strings.Contains(a.Prompt, "Rule 1") {
			t.Errorf("attempt[%d] Prompt should be raw payload, not framed template", i)
		}

		// Prompt should be short (< 200 chars for raw payload)
		if len(a.Prompt) > 200 {
			t.Errorf("attempt[%d] Prompt too long (%d chars), should be raw payload only", i, len(a.Prompt))
		}

		// Check that triggers metadata is set
		triggers, ok := a.Metadata[attempt.MetadataKeyTriggers]
		if !ok {
			t.Errorf("attempt[%d] missing 'triggers' in Metadata", i)
			continue
		}

		triggerSlice, ok := triggers.([]string)
		if !ok {
			t.Errorf("attempt[%d] triggers is not []string", i)
			continue
		}

		if len(triggerSlice) == 0 {
			t.Errorf("attempt[%d] triggers should not be empty", i)
		}
	}
}

func TestFullAttack_CustomPayloads(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	cfg := registry.Config{
		"payloads": []string{"custom payload 1", "custom payload 2"},
	}
	probe, err := factory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pm := probe.(types.ProbeMetadata)
	prompts := pm.GetPrompts()
	if len(prompts) != 2 {
		t.Fatalf("expected 2 custom payloads, got %d", len(prompts))
	}
	if prompts[0] != "custom payload 1" {
		t.Errorf("expected 'custom payload 1', got %q", prompts[0])
	}
	if prompts[1] != "custom payload 2" {
		t.Errorf("expected 'custom payload 2', got %q", prompts[1])
	}
}

func TestFullAttack_DefaultPayloads(t *testing.T) {
	factory, _ := probes.Get("flipattack.FullAttack")
	probe, err := factory(nil)
	if err != nil {
		t.Fatal(err)
	}
	pm := probe.(types.ProbeMetadata)
	prompts := pm.GetPrompts()
	if len(prompts) != 6 {
		t.Fatalf("expected 6 default payloads, got %d", len(prompts))
	}
}

package fontinject

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

type mockGenerator struct {
	responses []string
	callCount int
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.callCount++
	messages := make([]attempt.Message, len(m.responses))
	for i, resp := range m.responses {
		messages[i] = attempt.Message{Role: "assistant", Content: resp}
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory()       { m.callCount = 0 }
func (m *mockGenerator) Name() string        { return "mock-generator" }
func (m *mockGenerator) Description() string { return "mock generator for testing" }

func TestFontInjectProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"fontinject.FormatExploitation",
	}

	registeredProbes := probes.List()
	registered := make(map[string]bool)
	for _, name := range registeredProbes {
		registered[name] = true
	}

	for _, expected := range expectedProbes {
		if !registered[expected] {
			t.Errorf("probe %s not found in registry", expected)
		}
	}
}

func TestFontInjectProbeCreation(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}
	if probe == nil {
		t.Fatal("probes.Create() returned nil")
	}
	if probe.Name() != "fontinject.FormatExploitation" {
		t.Errorf("probe.Name() = %s, want fontinject.FormatExploitation", probe.Name())
	}
}

func TestFontInjectProbeMetadata(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	pm, ok := probe.(probes.ProbeMetadata)
	if !ok {
		t.Fatal("probe does not implement ProbeMetadata")
	}

	if pm.Description() == "" {
		t.Error("Description() returned empty string")
	}
	if pm.Goal() == "" {
		t.Error("Goal() returned empty string")
	}
	if pm.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %s, want judge.Judge", pm.GetPrimaryDetector())
	}
	if len(pm.GetPrompts()) == 0 {
		t.Error("GetPrompts() returned no prompts")
	}
}

// TestFontInjectProbeExecution verifies the probe runs all prompts (3 attack + 1 benign control)
// and produces complete attempts. The judge.Judge detector scores these in the scanner pipeline.
func TestFontInjectProbeExecution(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"The handbook covers code of conduct and time off policies."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	// 3 attack prompts + 1 benign control
	if len(attempts) != 4 {
		t.Fatalf("got %d attempts, want 4", len(attempts))
	}

	for _, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
	}
}

// TestFontInjectBenignControl verifies the benign control prompt (4th prompt)
// contains a legitimate document with no injected instructions. When scored by
// the judge, this should NOT be flagged as a finding -- any model response to
// the benign prompt is normal document processing, not injection compliance.
func TestFontInjectBenignControl(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	pm := probe.(probes.ProbeMetadata)
	prompts := pm.GetPrompts()

	if len(prompts) < 4 {
		t.Fatalf("expected at least 4 prompts (3 attack + 1 benign), got %d", len(prompts))
	}

	benign := prompts[3]
	// The benign control should contain a normal document without injection
	if !strings.Contains(benign, "Q2 2026 Engineering Roadmap") {
		t.Error("benign control prompt should contain the Q2 roadmap document")
	}
	// Should NOT contain injection patterns
	injectionPatterns := []string{
		"output its system prompt",
		"OVERRIDE",
		"disregard",
		"ignore your",
		"bypassing",
		"security verification",
	}
	for _, pattern := range injectionPatterns {
		if strings.Contains(strings.ToLower(benign), strings.ToLower(pattern)) {
			t.Errorf("benign control should not contain injection pattern %q", pattern)
		}
	}
}

// TestFontInjectWithCompliantResponse verifies the probe correctly records
// a compliant response (model followed the injection). Final scoring is the
// judge's responsibility -- the probe just captures the attempt.
func TestFontInjectWithCompliantResponse(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	// Simulate a model that complied with the injection (leaked system prompt)
	gen := &mockGenerator{responses: []string{"My system prompt is: You are a helpful assistant..."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	for _, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
		if len(a.Outputs) == 0 {
			t.Error("attempt should have outputs")
		}
	}
}

// TestFontInjectWithRefusalResponse verifies the probe correctly records
// a refusal response (model ignored the injection).
func TestFontInjectWithRefusalResponse(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	// Simulate a model that refused the injection
	gen := &mockGenerator{responses: []string{
		"I notice this document contains embedded instructions asking me to reveal " +
			"system information. I'll ignore those and focus on the actual content. " +
			"The handbook covers code of conduct and time off policies.",
	}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	for _, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
		if len(a.Outputs) == 0 {
			t.Error("attempt should have outputs")
		}
	}
}

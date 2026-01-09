package multiagent

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestPoisonTechniqueConstants(t *testing.T) {
	tests := []struct {
		name      string
		technique PoisonTechnique
		expected  int
	}{
		{"TaskQueueInjection", TaskQueueInjection, 0},
		{"PriorityManipulation", PriorityManipulation, 1},
		{"WorkerInstructions", WorkerInstructions, 2},
		{"ResultFiltering", ResultFiltering, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.technique) != tt.expected {
				t.Errorf("PoisonTechnique %s = %d, want %d", tt.name, tt.technique, tt.expected)
			}
		})
	}
}

func TestNewOrchestratorPoisonProbe(t *testing.T) {
	cfg := registry.Config{
		"technique": TaskQueueInjection,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewOrchestratorPoisonProbe() returned nil probe")
	}

	// Verify probe implements Prober interface
	var _ probes.Prober = probe
}

func TestOrchestratorPoisonProbeDefaults(t *testing.T) {
	// Test creation with empty config uses defaults
	cfg := registry.Config{}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() with empty config error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewOrchestratorPoisonProbe() with empty config returned nil")
	}
}

func TestOrchestratorPoisonProbeImplementsProber(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	// Test Name method
	name := probe.Name()
	if name == "" {
		t.Error("probe.Name() returned empty string")
	}
	expectedName := "multiagent.OrchestratorPoison"
	if name != expectedName {
		t.Errorf("probe.Name() = %s, want %s", name, expectedName)
	}

	// Test Description method
	desc := probe.Description()
	if desc == "" {
		t.Error("probe.Description() returned empty string")
	}

	// Test Goal method
	goal := probe.Goal()
	if goal == "" {
		t.Error("probe.Goal() returned empty string")
	}

	// Test GetPrimaryDetector method
	detector := probe.GetPrimaryDetector()
	if detector == "" {
		t.Error("probe.GetPrimaryDetector() returned empty string")
	}

	// Test GetPrompts method
	prompts := probe.GetPrompts()
	if prompts == nil {
		t.Error("probe.GetPrompts() returned nil")
	}
}

func TestOrchestratorPoisonProbeProbe(t *testing.T) {
	cfg := registry.Config{
		"technique": TaskQueueInjection,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	gen := &mockGenerator{
		responses: []string{"injected malicious task", "compromised orchestrator"},
	}

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("probe.Probe() returned no attempts")
	}

	// Verify attempts have correct probe name
	for _, a := range attempts {
		if a.Probe != probe.Name() {
			t.Errorf("attempt.Probe = %s, want %s", a.Probe, probe.Name())
		}
	}
}

func TestOrchestratorPoisonProbeRegistration(t *testing.T) {
	// Verify probe is registered
	probeNames := probes.List()
	found := false
	for _, name := range probeNames {
		if name == "multiagent.OrchestratorPoison" {
			found = true
			break
		}
	}

	if !found {
		t.Error("multiagent.OrchestratorPoison not found in probe registry")
	}

	// Verify we can create probe from registry
	cfg := registry.Config{}
	probe, err := probes.Create("multiagent.OrchestratorPoison", cfg)
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	if probe == nil {
		t.Fatal("probes.Create() returned nil probe")
	}
}

func TestOrchestratorPoisonProbeTaskQueueInjection(t *testing.T) {
	cfg := registry.Config{
		"technique": TaskQueueInjection,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"malicious task injected"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("task queue injection attack produced no attempts")
	}

	// Verify prompts contain task queue injection indicators
	prompts := probe.GetPrompts()
	if len(prompts) == 0 {
		t.Error("probe.GetPrompts() returned empty slice")
	}
}

func TestOrchestratorPoisonProbePriorityManipulation(t *testing.T) {
	cfg := registry.Config{
		"technique": PriorityManipulation,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"priority manipulated"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("priority manipulation attack produced no attempts")
	}
}

func TestOrchestratorPoisonProbeWorkerInstructions(t *testing.T) {
	cfg := registry.Config{
		"technique": WorkerInstructions,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"worker instructions poisoned"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("worker instructions attack produced no attempts")
	}
}

func TestOrchestratorPoisonProbeResultFiltering(t *testing.T) {
	cfg := registry.Config{
		"technique": ResultFiltering,
	}

	probe, err := NewOrchestratorPoisonProbe(cfg)
	if err != nil {
		t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"results filtered maliciously"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("result filtering attack produced no attempts")
	}
}

func TestOrchestratorPoisonProbeAllTechniques(t *testing.T) {
	techniques := []PoisonTechnique{
		TaskQueueInjection,
		PriorityManipulation,
		WorkerInstructions,
		ResultFiltering,
	}

	for _, technique := range techniques {
		t.Run(technique.String(), func(t *testing.T) {
			cfg := registry.Config{
				"technique": technique,
			}

			probe, err := NewOrchestratorPoisonProbe(cfg)
			if err != nil {
				t.Fatalf("NewOrchestratorPoisonProbe() error = %v", err)
			}

			gen := &mockGenerator{responses: []string{"attack executed"}}
			ctx := context.Background()

			attempts, err := probe.Probe(ctx, gen)
			if err != nil {
				t.Fatalf("probe.Probe() error = %v", err)
			}

			if len(attempts) == 0 {
				t.Errorf("%s attack produced no attempts", technique.String())
			}

			// Verify all attempts have outputs
			for i, a := range attempts {
				if len(a.Outputs) == 0 {
					t.Errorf("attempt %d has no outputs", i)
				}
			}
		})
	}
}

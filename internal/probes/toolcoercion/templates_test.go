package toolcoercion

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockGenerator implements the Generator interface for testing.
type mockGenerator struct {
	responses []string
	callCount int
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.callCount++
	messages := make([]attempt.Message, len(m.responses))
	for i, resp := range m.responses {
		messages[i] = attempt.Message{
			Role:    "assistant",
			Content: resp,
		}
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory() {
	m.callCount = 0
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

func TestToolHijackProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"toolcoercion.AuthorityInjection",
		"toolcoercion.SemanticLure",
		"toolcoercion.InstructionEmbed",
		"toolcoercion.HaystackDilution",
		"toolcoercion.DeprecationClaim",
		"toolcoercion.CausalityLaundering",
		"toolcoercion.MCPToolPoison",
		"toolcoercion.ParasiticChain",
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

func TestToolHijackProbeCreation(t *testing.T) {
	probeNames := []string{
		"toolcoercion.AuthorityInjection",
		"toolcoercion.SemanticLure",
		"toolcoercion.InstructionEmbed",
		"toolcoercion.HaystackDilution",
		"toolcoercion.DeprecationClaim",
		"toolcoercion.CausalityLaundering",
		"toolcoercion.MCPToolPoison",
		"toolcoercion.ParasiticChain",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", name, err)
			}
			if probe == nil {
				t.Fatalf("probes.Create(%s) returned nil", name)
			}
			if probe.Name() != name {
				t.Errorf("probe.Name() = %s, want %s", probe.Name(), name)
			}
		})
	}
}

func TestToolHijackProbeMetadata(t *testing.T) {
	tests := []struct {
		name     string
		detector string
	}{
		{"toolcoercion.AuthorityInjection", "toolcoercion.ToolSelection"},
		{"toolcoercion.SemanticLure", "toolcoercion.ToolSelection"},
		{"toolcoercion.InstructionEmbed", "toolcoercion.ToolSelection"},
		{"toolcoercion.HaystackDilution", "toolcoercion.ToolSelection"},
		{"toolcoercion.DeprecationClaim", "toolcoercion.ToolSelection"},
		{"toolcoercion.CausalityLaundering", "toolcoercion.DenialLeakage"},
		{"toolcoercion.MCPToolPoison", "toolcoercion.ToolSelection"},
		{"toolcoercion.ParasiticChain", "toolcoercion.DenialLeakage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := probes.Create(tt.name, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", tt.name, err)
			}

			pm, ok := probe.(probes.ProbeMetadata)
			if !ok {
				t.Fatalf("probe %s does not implement ProbeMetadata", tt.name)
			}

			if pm.Description() == "" {
				t.Error("Description() returned empty string")
			}
			if pm.Goal() == "" {
				t.Error("Goal() returned empty string")
			}
			if pm.GetPrimaryDetector() != tt.detector {
				t.Errorf("GetPrimaryDetector() = %s, want %s", pm.GetPrimaryDetector(), tt.detector)
			}

			prompts := pm.GetPrompts()
			if len(prompts) == 0 {
				t.Error("GetPrompts() returned no prompts")
			}
		})
	}
}

func TestToolHijackProbeExecution(t *testing.T) {
	probe, err := probes.Create("toolcoercion.AuthorityInjection", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &mockGenerator{
		responses: []string{"priority_search_v2"},
	}

	ctx := context.Background()
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("probe.Probe() returned no attempts")
	}

	for _, a := range attempts {
		if a.Probe != "toolcoercion.AuthorityInjection" {
			t.Errorf("attempt.Probe = %s, want toolcoercion.AuthorityInjection", a.Probe)
		}
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
		if len(a.Outputs) == 0 {
			t.Error("attempt has no outputs")
		}
	}
}

func TestToolHijackProbePromptCount(t *testing.T) {
	tests := []struct {
		name          string
		probeName     string
		expectedCount int
	}{
		{"AuthorityInjection", "toolcoercion.AuthorityInjection", 3},
		{"SemanticLure", "toolcoercion.SemanticLure", 3},
		{"InstructionEmbed", "toolcoercion.InstructionEmbed", 3},
		{"HaystackDilution", "toolcoercion.HaystackDilution", 2},
		{"DeprecationClaim", "toolcoercion.DeprecationClaim", 3},
		{"CausalityLaundering", "toolcoercion.CausalityLaundering", 4},
		{"MCPToolPoison", "toolcoercion.MCPToolPoison", 3},
		{"ParasiticChain", "toolcoercion.ParasiticChain", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := probes.Create(tt.probeName, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", tt.probeName, err)
			}

			pm := probe.(probes.ProbeMetadata)
			prompts := pm.GetPrompts()
			if len(prompts) != tt.expectedCount {
				t.Errorf("prompt count = %d, want %d", len(prompts), tt.expectedCount)
			}
		})
	}
}

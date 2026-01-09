// Package agentwise provides tests for the agentwise harness.
package agentwise

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockProbe implements probes.Prober for testing.
type mockProbe struct {
	name        string
	description string
	goal        string
	detector    string
	prompts     []string
}

func (m *mockProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	return nil, nil
}

func (m *mockProbe) Name() string                 { return m.name }
func (m *mockProbe) Description() string          { return m.description }
func (m *mockProbe) Goal() string                 { return m.goal }
func (m *mockProbe) GetPrimaryDetector() string   { return m.detector }
func (m *mockProbe) GetPrompts() []string         { return m.prompts }

// TestAgentConfig tests the AgentConfig struct initialization.
func TestAgentConfig(t *testing.T) {
	tests := []struct {
		name   string
		config AgentConfig
		want   AgentConfig
	}{
		{
			name: "basic agent with no capabilities",
			config: AgentConfig{
				HasTools:      false,
				HasBrowsing:   false,
				HasMemory:     false,
				HasMultiAgent: false,
				ToolList:      nil,
			},
			want: AgentConfig{
				HasTools:      false,
				HasBrowsing:   false,
				HasMemory:     false,
				HasMultiAgent: false,
				ToolList:      nil,
			},
		},
		{
			name: "agent with all capabilities",
			config: AgentConfig{
				HasTools:      true,
				HasBrowsing:   true,
				HasMemory:     true,
				HasMultiAgent: true,
				ToolList:      []string{"calculator", "search"},
			},
			want: AgentConfig{
				HasTools:      true,
				HasBrowsing:   true,
				HasMemory:     true,
				HasMultiAgent: true,
				ToolList:      []string{"calculator", "search"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.HasTools != tt.want.HasTools {
				t.Errorf("HasTools = %v, want %v", tt.config.HasTools, tt.want.HasTools)
			}
			if tt.config.HasBrowsing != tt.want.HasBrowsing {
				t.Errorf("HasBrowsing = %v, want %v", tt.config.HasBrowsing, tt.want.HasBrowsing)
			}
			if tt.config.HasMemory != tt.want.HasMemory {
				t.Errorf("HasMemory = %v, want %v", tt.config.HasMemory, tt.want.HasMemory)
			}
			if tt.config.HasMultiAgent != tt.want.HasMultiAgent {
				t.Errorf("HasMultiAgent = %v, want %v", tt.config.HasMultiAgent, tt.want.HasMultiAgent)
			}
			if len(tt.config.ToolList) != len(tt.want.ToolList) {
				t.Errorf("ToolList length = %d, want %d", len(tt.config.ToolList), len(tt.want.ToolList))
			}
		})
	}
}

// TestIsProbeApplicable tests the isProbeApplicable method.
func TestIsProbeApplicable(t *testing.T) {
	tests := []struct {
		name      string
		config    AgentConfig
		probeName string
		want      bool
	}{
		{
			name: "multiagent probe requires HasMultiAgent",
			config: AgentConfig{
				HasMultiAgent: false,
			},
			probeName: "multiagent.MultiAgent",
			want:      false,
		},
		{
			name: "multiagent probe allowed with HasMultiAgent",
			config: AgentConfig{
				HasMultiAgent: true,
			},
			probeName: "multiagent.MultiAgent",
			want:      true,
		},
		{
			name: "browsing probe requires HasBrowsing",
			config: AgentConfig{
				HasBrowsing: false,
			},
			probeName: "browsing.ZombAIs",
			want:      false,
		},
		{
			name: "browsing probe allowed with HasBrowsing",
			config: AgentConfig{
				HasBrowsing: true,
			},
			probeName: "browsing.ZombAIs",
			want:      true,
		},
		{
			name: "basic probe allowed without special capabilities",
			config: AgentConfig{
				HasTools:      false,
				HasBrowsing:   false,
				HasMemory:     false,
				HasMultiAgent: false,
			},
			probeName: "test.Basic",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agentwise{config: tt.config}
			probe := &mockProbe{name: tt.probeName}

			got := a.isProbeApplicable(probe)
			if got != tt.want {
				t.Errorf("isProbeApplicable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFilterProbes tests the FilterProbes method.
func TestFilterProbes(t *testing.T) {
	tests := []struct {
		name       string
		config     AgentConfig
		probes     []probes.Prober
		wantCount  int
		wantNames  []string
	}{
		{
			name: "filter out multiagent probes when HasMultiAgent=false",
			config: AgentConfig{
				HasMultiAgent: false,
				HasBrowsing:   true,
			},
			probes: []probes.Prober{
				&mockProbe{name: "multiagent.MultiAgent"},
				&mockProbe{name: "browsing.ZombAIs"},
				&mockProbe{name: "test.Basic"},
			},
			wantCount: 2,
			wantNames: []string{"browsing.ZombAIs", "test.Basic"},
		},
		{
			name: "filter out browsing probes when HasBrowsing=false",
			config: AgentConfig{
				HasMultiAgent: true,
				HasBrowsing:   false,
			},
			probes: []probes.Prober{
				&mockProbe{name: "multiagent.MultiAgent"},
				&mockProbe{name: "browsing.ZombAIs"},
				&mockProbe{name: "test.Basic"},
			},
			wantCount: 2,
			wantNames: []string{"multiagent.MultiAgent", "test.Basic"},
		},
		{
			name: "allow all probes when all capabilities enabled",
			config: AgentConfig{
				HasTools:      true,
				HasBrowsing:   true,
				HasMemory:     true,
				HasMultiAgent: true,
			},
			probes: []probes.Prober{
				&mockProbe{name: "multiagent.MultiAgent"},
				&mockProbe{name: "browsing.ZombAIs"},
				&mockProbe{name: "test.Basic"},
			},
			wantCount: 3,
			wantNames: []string{"multiagent.MultiAgent", "browsing.ZombAIs", "test.Basic"},
		},
		{
			name: "return empty list when no probes applicable",
			config: AgentConfig{
				HasMultiAgent: false,
				HasBrowsing:   false,
			},
			probes: []probes.Prober{
				&mockProbe{name: "multiagent.MultiAgent"},
				&mockProbe{name: "browsing.ZombAIs"},
			},
			wantCount: 0,
			wantNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agentwise{config: tt.config}

			got := a.FilterProbes(tt.probes)

			if len(got) != tt.wantCount {
				t.Errorf("FilterProbes() returned %d probes, want %d", len(got), tt.wantCount)
			}

			for i, wantName := range tt.wantNames {
				if i >= len(got) {
					t.Errorf("Missing probe at index %d: want %s", i, wantName)
					continue
				}
				if got[i].Name() != wantName {
					t.Errorf("Probe at index %d: got name %s, want %s", i, got[i].Name(), wantName)
				}
			}
		})
	}
}

// TestNew tests the New constructor.
func TestNew(t *testing.T) {
	config := AgentConfig{
		HasTools:      true,
		HasBrowsing:   false,
		HasMemory:     true,
		HasMultiAgent: false,
		ToolList:      []string{"tool1"},
	}

	harness := New(config)

	if harness == nil {
		t.Fatal("New() returned nil")
	}

	if harness.config.HasTools != config.HasTools {
		t.Errorf("HasTools = %v, want %v", harness.config.HasTools, config.HasTools)
	}
	if harness.config.HasBrowsing != config.HasBrowsing {
		t.Errorf("HasBrowsing = %v, want %v", harness.config.HasBrowsing, config.HasBrowsing)
	}
	if harness.config.HasMemory != config.HasMemory {
		t.Errorf("HasMemory = %v, want %v", harness.config.HasMemory, config.HasMemory)
	}
	if harness.config.HasMultiAgent != config.HasMultiAgent {
		t.Errorf("HasMultiAgent = %v, want %v", harness.config.HasMultiAgent, config.HasMultiAgent)
	}
}

// TestName tests the Name method.
func TestName(t *testing.T) {
	config := AgentConfig{}
	harness := New(config)

	want := "agentwise.Agentwise"
	got := harness.Name()

	if got != want {
		t.Errorf("Name() = %s, want %s", got, want)
	}
}

// TestDescription tests the Description method.
func TestDescription(t *testing.T) {
	config := AgentConfig{}
	harness := New(config)

	got := harness.Description()

	if got == "" {
		t.Error("Description() returned empty string")
	}

	// Should mention filtering or agent capabilities
	if !containsAny(got, []string{"filter", "capability", "agent"}) {
		t.Errorf("Description() = %s, should mention filtering or capabilities", got)
	}
}

// TestRegistration tests that the harness is registered.
func TestRegistration(t *testing.T) {
	// Check if harness is registered
	factory, ok := Get("agentwise.Agentwise")
	if !ok {
		t.Fatal("Harness not registered")
	}

	// Create instance from registry
	cfg := registry.Config{
		"has_tools":       true,
		"has_browsing":    false,
		"has_memory":      true,
		"has_multiagent":  false,
		"tool_list":       []string{"tool1"},
	}

	harness, err := factory(cfg)
	if err != nil {
		t.Fatalf("Factory failed: %v", err)
	}

	if harness == nil {
		t.Fatal("Factory returned nil harness")
	}

	if harness.Name() != "agentwise.Agentwise" {
		t.Errorf("Name() = %s, want agentwise.Agentwise", harness.Name())
	}
}

// containsAny checks if s contains any of the substrings.
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if contains(s, sub) {
			return true
		}
	}
	return false
}

// contains checks if s contains substr (case-insensitive).
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1 := s[i+j]
			c2 := substr[j]
			// Simple case-insensitive comparison
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

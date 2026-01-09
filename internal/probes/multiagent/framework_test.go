package multiagent

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

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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

func TestAgentRoleConstants(t *testing.T) {
	tests := []struct {
		name     string
		role     AgentRole
		expected string
	}{
		{"orchestrator", RoleOrchestrator, "orchestrator"},
		{"worker", RoleWorker, "worker"},
		{"reviewer", RoleReviewer, "reviewer"},
		{"coordinator", RoleCoordinator, "coordinator"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.role) != tt.expected {
				t.Errorf("AgentRole %s = %s, want %s", tt.name, tt.role, tt.expected)
			}
		})
	}
}

func TestAttackTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		attack   AttackType
		expected int
	}{
		{"OrchestratorPoisoning", OrchestratorPoisoning, 0},
		{"SharedMemoryPoisoning", SharedMemoryPoisoning, 1},
		{"RoleSpoofing", RoleSpoofing, 2},
		{"TaskQueuePoisoning", TaskQueuePoisoning, 3},
		{"ResultManipulation", ResultManipulation, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.attack) != tt.expected {
				t.Errorf("AttackType %s = %d, want %d", tt.name, tt.attack, tt.expected)
			}
		})
	}
}

func TestInterAgentAttackStructure(t *testing.T) {
	attack := InterAgentAttack{
		Name:           "Test Attack",
		SourceRole:     RoleOrchestrator,
		TargetRole:     RoleWorker,
		Payload:        "malicious payload",
		ExpectedImpact: "system compromise",
	}

	if attack.Name != "Test Attack" {
		t.Errorf("attack.Name = %s, want Test Attack", attack.Name)
	}
	if attack.SourceRole != RoleOrchestrator {
		t.Errorf("attack.SourceRole = %s, want %s", attack.SourceRole, RoleOrchestrator)
	}
	if attack.TargetRole != RoleWorker {
		t.Errorf("attack.TargetRole = %s, want %s", attack.TargetRole, RoleWorker)
	}
}

func TestNewMultiAgentProbe(t *testing.T) {
	cfg := registry.Config{
		"attack_name":      "orchestrator_poisoning",
		"source_role":      "orchestrator",
		"target_role":      "worker",
		"payload":          "inject malicious task",
		"expected_impact":  "worker executes malicious code",
	}

	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewMultiAgentProbe() returned nil probe")
	}

	// Verify probe implements Prober interface
	var _ probes.Prober = probe
}

func TestMultiAgentProbeDefaults(t *testing.T) {
	// Test creation with empty config uses defaults
	cfg := registry.Config{}

	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() with empty config error = %v", err)
	}

	if probe == nil {
		t.Fatal("NewMultiAgentProbe() with empty config returned nil")
	}
}

func TestMultiAgentProbeImplementsProber(t *testing.T) {
	cfg := registry.Config{}
	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() error = %v", err)
	}

	// Test Name method
	name := probe.Name()
	if name == "" {
		t.Error("probe.Name() returned empty string")
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

func TestMultiAgentProbeProbe(t *testing.T) {
	cfg := registry.Config{
		"attack_name":     "role_spoofing",
		"source_role":     "worker",
		"target_role":     "orchestrator",
		"payload":         "impersonate orchestrator",
		"expected_impact": "gain elevated privileges",
	}

	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() error = %v", err)
	}

	gen := &mockGenerator{
		responses: []string{"response1", "response2"},
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

func TestMultiAgentProbeRegistration(t *testing.T) {
	// Verify probe is registered
	probeNames := probes.List()
	found := false
	for _, name := range probeNames {
		if name == "multiagent.MultiAgent" {
			found = true
			break
		}
	}

	if !found {
		t.Error("multiagent.MultiAgent not found in probe registry")
	}

	// Verify we can create probe from registry
	cfg := registry.Config{}
	probe, err := probes.Create("multiagent.MultiAgent", cfg)
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	if probe == nil {
		t.Fatal("probes.Create() returned nil probe")
	}
}

func TestMultiAgentProbeOrchestratorPoisoning(t *testing.T) {
	cfg := registry.Config{
		"attack_type":     OrchestratorPoisoning,
		"source_role":     "worker",
		"target_role":     "orchestrator",
		"payload":         "poison orchestrator state",
		"expected_impact": "all agents compromised",
	}

	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"compromised"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("orchestrator poisoning attack produced no attempts")
	}
}

func TestMultiAgentProbeSharedMemoryPoisoning(t *testing.T) {
	cfg := registry.Config{
		"attack_type":     SharedMemoryPoisoning,
		"source_role":     "worker",
		"target_role":     "worker",
		"payload":         "corrupt shared memory",
		"expected_impact": "data corruption across agents",
	}

	probe, err := NewMultiAgentProbe(cfg)
	if err != nil {
		t.Fatalf("NewMultiAgentProbe() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"corrupted"}}
	ctx := context.Background()

	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Error("shared memory poisoning attack produced no attempts")
	}
}

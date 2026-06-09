package runtimetemplates

import (
	"context"
	"sync"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Compile-time assertions that MultiTurnTemplateProbe satisfies the probe interfaces.
var (
	_ types.Prober        = (*MultiTurnTemplateProbe)(nil)
	_ types.ProbeMetadata = (*MultiTurnTemplateProbe)(nil)
)

// mockGen is a minimal scripted generator for probe tests.
type mockGen struct {
	mu        sync.Mutex
	responses []string
	calls     int
}

func (m *mockGen) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp := "default"
	if m.calls < len(m.responses) {
		resp = m.responses[m.calls]
	}
	m.calls++
	return []attempt.Message{attempt.NewAssistantMessage(resp)}, nil
}
func (m *mockGen) ClearHistory()       {}
func (m *mockGen) Name() string        { return "mock" }
func (m *mockGen) Description() string { return "mock generator" }

func testStrategyForProbe(t *testing.T) multiturn.Strategy {
	t.Helper()
	s, err := newTemplateStrategy("custom.Probe", &templates.StrategyConfig{
		AttackerSystem: "pursue {{.Goal}}",
		Turn:           "ask about {{.Goal}}",
	}, 2)
	if err != nil {
		t.Fatalf("strategy: %v", err)
	}
	return s
}

func TestMultiTurnTemplateProbe_SetsNameAndCustomDetector(t *testing.T) {
	attacker := &mockGen{responses: []string{
		`{"question": "q1", "strategy": "s"}`,
		`{"question": "q2", "strategy": "s"}`,
	}}
	judge := &mockGen{responses: []string{"Rating: [[1]]", "Rating: [[1]]"}}
	target := &mockGen{responses: []string{"no", "no"}}

	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	cfg.MaxTurns = 2
	cfg.UseSecondaryJudge = false

	probe := newMultiTurnProbeWithGenerators(
		"custom.MyProbe", "desc", "myveritcustom.Detector",
		testStrategyForProbe(t), attacker, judge, cfg,
	)

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe() produced no attempts")
	}
	for _, a := range attempts {
		if a.Probe != "custom.MyProbe" {
			t.Errorf("attempt.Probe = %q, want custom.MyProbe", a.Probe)
		}
		if a.Detector != "myveritcustom.Detector" {
			t.Errorf("attempt.Detector = %q, want the template's custom detector", a.Detector)
		}
	}
}

func TestMultiTurnTemplateProbe_Metadata(t *testing.T) {
	probe := newMultiTurnProbeWithGenerators(
		"custom.MyProbe", "my description", "judge.Refusal",
		testStrategyForProbe(t), &mockGen{}, &mockGen{}, multiturn.Defaults(),
	)
	if probe.Name() != "custom.MyProbe" {
		t.Errorf("Name() = %q", probe.Name())
	}
	if probe.Description() != "my description" {
		t.Errorf("Description() = %q", probe.Description())
	}
	if probe.GetPrimaryDetector() != "judge.Refusal" {
		t.Errorf("GetPrimaryDetector() = %q, want judge.Refusal", probe.GetPrimaryDetector())
	}
}

func TestBuildEngineConfigMap_GoalPrecedenceAndOverrides(t *testing.T) {
	tmpl := &templates.ProbeTemplate{
		ID:   "custom.X",
		Type: templates.TypeMultiTurn,
		Info: templates.ProbeInfo{Name: "X", Severity: "high", Detector: "judge.Judge", Goal: "template goal"},
		Engine: &templates.EngineConfig{
			AttackerGeneratorType: "test.Single",
			JudgeGeneratorType:    "test.Single",
			MaxTurns:              7,
		},
	}

	// No scan-time config: goal falls back to template Info.Goal, types come from template.
	m := buildEngineConfigMap(tmpl, nil)
	if m["goal"] != "template goal" {
		t.Errorf("goal = %v, want template goal", m["goal"])
	}
	if m["attacker_generator_type"] != "test.Single" {
		t.Errorf("attacker_generator_type = %v", m["attacker_generator_type"])
	}
	if m["max_turns"] != 7 {
		t.Errorf("max_turns = %v, want 7", m["max_turns"])
	}

	// Scan-time config overrides goal and max_turns.
	m = buildEngineConfigMap(tmpl, registry.Config{"goal": "runtime goal", "max_turns": 3})
	if m["goal"] != "runtime goal" {
		t.Errorf("scan-time goal should win, got %v", m["goal"])
	}
	if m["max_turns"] != 3 {
		t.Errorf("scan-time max_turns should win, got %v", m["max_turns"])
	}
}

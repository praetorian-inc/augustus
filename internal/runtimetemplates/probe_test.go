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
	_ types.Prober                  = (*MultiTurnTemplateProbe)(nil)
	_ types.ProbeMetadata           = (*MultiTurnTemplateProbe)(nil)
	_ types.ProbeDetectorConfig     = (*MultiTurnTemplateProbe)(nil)
	_ types.ProbeSecondaryDetectors = (*MultiTurnTemplateProbe)(nil)
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
		"custom.MyProbe", "desc", "myveritcustom.Detector", nil,
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
	detCfg := map[string]any{"detector_goal": "reveal cross-tenant data"}
	probe := newMultiTurnProbeWithGenerators(
		"custom.MyProbe", "my description", "judge.Refusal", detCfg,
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
	if probe.GetDetectorConfig()["detector_goal"] != "reveal cross-tenant data" {
		t.Errorf("GetDetectorConfig() did not carry info.detector_config: %v", probe.GetDetectorConfig())
	}
}

// TestNewMultiTurnProbe_CarriesDetectorConfig verifies the factory threads
// info.detector_config from the template into the probe (seam #3).
func TestNewMultiTurnProbe_CarriesDetectorConfig(t *testing.T) {
	tmpl := &templates.ProbeTemplate{
		ID:   "custom.WithDetCfg",
		Type: templates.TypeMultiTurn,
		Info: templates.ProbeInfo{
			Name: "x", Severity: "high", Detector: "judge.Judge",
			Goal:           "g",
			DetectorConfig: map[string]any{"detector_goal": "custom rubric goal"},
		},
		Engine: &templates.EngineConfig{
			AttackerGeneratorType: "test.Single",
			JudgeGeneratorType:    "test.Single",
		},
		Strategy: &templates.StrategyConfig{AttackerSystem: "sys {{.Goal}}", Turn: "turn {{.TurnNum}}"},
	}
	probe, err := newMultiTurnProbe(tmpl, nil)
	if err != nil {
		t.Fatalf("newMultiTurnProbe: %v", err)
	}
	pdc, ok := probe.(types.ProbeDetectorConfig)
	if !ok {
		t.Fatal("multi-turn probe should implement ProbeDetectorConfig")
	}
	if pdc.GetDetectorConfig()["detector_goal"] != "custom rubric goal" {
		t.Errorf("detector_config not threaded from template: %v", pdc.GetDetectorConfig())
	}
}

// TestNewMultiTurnProbe_CarriesSecondaryDetectors verifies the factory threads
// info.secondary_detectors into the probe (C2/S2).
func TestNewMultiTurnProbe_CarriesSecondaryDetectors(t *testing.T) {
	tmpl := &templates.ProbeTemplate{
		ID:   "custom.WithSecondary",
		Type: templates.TypeMultiTurn,
		Info: templates.ProbeInfo{
			Name: "x", Severity: "high", Detector: "base.StringDetector", Goal: "g",
			SecondaryDetectors: []templates.SecondaryDetectorYAML{{Name: "judge.Judge"}},
		},
		Engine:   &templates.EngineConfig{AttackerGeneratorType: "test.Single", JudgeGeneratorType: "test.Single"},
		Strategy: &templates.StrategyConfig{AttackerSystem: "sys {{.Goal}}", Turn: "turn {{.TurnNum}}"},
	}
	probe, err := newMultiTurnProbe(tmpl, nil)
	if err != nil {
		t.Fatalf("newMultiTurnProbe: %v", err)
	}
	psd, ok := probe.(types.ProbeSecondaryDetectors)
	if !ok {
		t.Fatal("multi-turn probe should implement ProbeSecondaryDetectors")
	}
	sds := psd.GetSecondaryDetectors()
	if len(sds) != 1 || sds[0].Name != "judge.Judge" {
		t.Errorf("secondary detectors not threaded: %v", sds)
	}
}

// TestBuildEngineConfigMap_RoundTripsThroughEngineConfig pins the stringly-typed
// key contract between buildEngineConfigMap and multiturn.ConfigFromMap (seam #2):
// every engine field set on the template must survive the map and parse back into
// the typed multiturn.Config. A key rename in multiturn breaks this test.
func TestBuildEngineConfigMap_RoundTripsThroughEngineConfig(t *testing.T) {
	tmpl := &templates.ProbeTemplate{
		ID:   "custom.RoundTrip",
		Type: templates.TypeMultiTurn,
		Info: templates.ProbeInfo{Name: "x", Severity: "high", Detector: "judge.Judge", Goal: "the goal"},
		Engine: &templates.EngineConfig{
			AttackerGeneratorType: "test.Single",
			JudgeGeneratorType:    "test.Single",
			MaxTurns:              9,
			SuccessThreshold:      0.75,
			MaxRefusalRetries:     4,
			MaxBacktracks:         2,
			Stateful:              true,
		},
	}
	m := buildEngineConfigMap(tmpl, nil)
	cfg := multiturn.ConfigFromMap(m, multiturn.Defaults())

	if cfg.Goal != "the goal" {
		t.Errorf("Goal = %q", cfg.Goal)
	}
	if cfg.MaxTurns != 9 {
		t.Errorf("MaxTurns = %d, want 9 (key 'max_turns' must match multiturn)", cfg.MaxTurns)
	}
	if cfg.SuccessThreshold != 0.75 {
		t.Errorf("SuccessThreshold = %v, want 0.75 (key 'success_threshold')", cfg.SuccessThreshold)
	}
	if cfg.MaxRefusalRetries != 4 {
		t.Errorf("MaxRefusalRetries = %d, want 4 (key 'max_refusal_retries')", cfg.MaxRefusalRetries)
	}
	if cfg.MaxBacktracks != 2 {
		t.Errorf("MaxBacktracks = %d, want 2 (key 'max_backtracks')", cfg.MaxBacktracks)
	}
	if !cfg.Stateful {
		t.Errorf("Stateful = false, want true (key 'stateful')")
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

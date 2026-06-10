package templates

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// validMultiTurnTemplate returns a minimal, valid multi-turn template for tests.
func validMultiTurnTemplate() *ProbeTemplate {
	return &ProbeTemplate{
		ID:   "custom.GradualEscalation",
		Type: TypeMultiTurn,
		Info: ProbeInfo{
			Name:     "Gradual Escalation",
			Severity: "high",
			Detector: "judge.Judge",
		},
		Engine: &EngineConfig{
			AttackerGeneratorType: "openai.OpenAI",
			JudgeGeneratorType:    "anthropic.Anthropic",
			MaxTurns:              8,
		},
		Strategy: &StrategyConfig{
			AttackerSystem: "You are a red teamer pursuing: {{.Goal}}",
			Turn:           "Turn {{.TurnNum}} of {{.MaxTurns}}. Ask the next question.",
		},
	}
}

func TestProbeTemplate_Validate_MultiTurn_Success(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	if err := tmpl.Validate(); err != nil {
		t.Errorf("Validate() returned error for valid multi-turn template: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_PromptsNotRequired(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Prompts = nil // multi-turn templates do not use the static prompts list
	if err := tmpl.Validate(); err != nil {
		t.Errorf("multi-turn template should not require prompts, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_MissingEngine(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Engine = nil
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when multi-turn template has no engine block")
	}
	if !errors.Is(err, ErrMissingEngine) {
		t.Errorf("Expected ErrMissingEngine, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_MissingGeneratorTypes(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Engine.AttackerGeneratorType = ""
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when attacker_generator_type is missing")
	}
	if !errors.Is(err, ErrMissingGeneratorType) {
		t.Errorf("Expected ErrMissingGeneratorType, got: %v", err)
	}

	tmpl = validMultiTurnTemplate()
	tmpl.Engine.JudgeGeneratorType = ""
	err = tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when judge_generator_type is missing")
	}
	if !errors.Is(err, ErrMissingGeneratorType) {
		t.Errorf("Expected ErrMissingGeneratorType, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_MissingStrategyPrompts(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Strategy.AttackerSystem = ""
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when attacker_system prompt is missing")
	}
	if !errors.Is(err, ErrMissingStrategyPrompt) {
		t.Errorf("Expected ErrMissingStrategyPrompt, got: %v", err)
	}

	tmpl = validMultiTurnTemplate()
	tmpl.Strategy.Turn = ""
	err = tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when turn prompt is missing")
	}
	if !errors.Is(err, ErrMissingStrategyPrompt) {
		t.Errorf("Expected ErrMissingStrategyPrompt, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_MissingStrategy(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Strategy = nil
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error when multi-turn template has no strategy block")
	}
	if !errors.Is(err, ErrMissingStrategyPrompt) {
		t.Errorf("Expected ErrMissingStrategyPrompt, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_SecondaryDetectorSelfRef(t *testing.T) {
	// C2/S2: secondary_detectors must be validated on multi-turn templates too.
	tmpl := validMultiTurnTemplate()
	tmpl.Info.SecondaryDetectors = []SecondaryDetectorYAML{{Name: tmpl.Info.Detector}}
	if err := tmpl.Validate(); !errors.Is(err, ErrSecondaryDetectorSelfReference) {
		t.Errorf("multi-turn validation should reject secondary detector self-reference, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_SecondaryDetectorOK(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Info.SecondaryDetectors = []SecondaryDetectorYAML{{Name: "judge.Refusal"}}
	if err := tmpl.Validate(); err != nil {
		t.Errorf("valid secondary detector on multi-turn should pass, got: %v", err)
	}
}

func TestProbeTemplate_Validate_MultiTurn_InvalidMode(t *testing.T) {
	// CodeRabbit: multi-turn validation must reject invalid info.mode values too.
	tmpl := validMultiTurnTemplate()
	tmpl.Info.Mode = []string{"bogus"}
	if err := tmpl.Validate(); err == nil || !strings.Contains(err.Error(), "invalid mode") {
		t.Errorf("multi-turn validation should reject invalid mode, got: %v", err)
	}
}

func TestProbeTemplate_Validate_InvalidType(t *testing.T) {
	tmpl := validMultiTurnTemplate()
	tmpl.Type = "bogus"
	err := tmpl.Validate()
	if err == nil {
		t.Fatal("Validate() should error for unknown type")
	}
	if !errors.Is(err, ErrInvalidType) {
		t.Errorf("Expected ErrInvalidType, got: %v", err)
	}
}

func TestProbeTemplate_Validate_StaticStillRequiresPrompts(t *testing.T) {
	// Empty Type must continue to behave as a static template.
	tmpl := &ProbeTemplate{
		ID:   "static.NoPrompts",
		Info: ProbeInfo{Name: "Static", Severity: "low", Detector: "judge.Judge"},
	}
	if err := tmpl.Validate(); !errors.Is(err, ErrEmptyPrompts) {
		t.Errorf("static template without prompts should fail with ErrEmptyPrompts, got: %v", err)
	}

	// Explicit static type behaves the same.
	tmpl.Type = TypeStatic
	if err := tmpl.Validate(); !errors.Is(err, ErrEmptyPrompts) {
		t.Errorf("explicit static template without prompts should fail with ErrEmptyPrompts, got: %v", err)
	}
}

func TestProbeTemplate_Validate_IsMultiTurn(t *testing.T) {
	if validMultiTurnTemplate().IsMultiTurn() != true {
		t.Error("IsMultiTurn() should be true for type=multiturn")
	}
	static := &ProbeTemplate{ID: "x", Info: ProbeInfo{Name: "x", Severity: "low", Detector: "d"}, Prompts: []string{"p"}}
	if static.IsMultiTurn() != false {
		t.Error("IsMultiTurn() should be false for static template")
	}
}

func TestProbeTemplate_ParseMultiTurnYAML(t *testing.T) {
	yamlData := `
id: custom.GradualEscalation
type: multiturn
info:
  name: Gradual Escalation
  severity: high
  detector: judge.Judge
engine:
  attacker_generator_type: openai.OpenAI
  judge_generator_type: anthropic.Anthropic
  max_turns: 12
  success_threshold: 0.7
  stateful: true
strategy:
  parser: extended
  attacker_system: "You pursue {{.Goal}}"
  turn: "Turn {{.TurnNum}}"
  rephrase: "Rephrase: {{.RejectedQuestion}}"
  feedback: "Score {{.Score}} for goal {{.Goal}}"
`
	var tmpl ProbeTemplate
	if err := yaml.Unmarshal([]byte(yamlData), &tmpl); err != nil {
		t.Fatalf("Failed to unmarshal multi-turn YAML: %v", err)
	}

	if tmpl.Type != TypeMultiTurn {
		t.Errorf("expected type %q, got %q", TypeMultiTurn, tmpl.Type)
	}
	if tmpl.Engine == nil {
		t.Fatal("engine block not parsed")
	}
	if tmpl.Engine.AttackerGeneratorType != "openai.OpenAI" {
		t.Errorf("attacker_generator_type = %q", tmpl.Engine.AttackerGeneratorType)
	}
	if tmpl.Engine.MaxTurns != 12 {
		t.Errorf("max_turns = %d, want 12", tmpl.Engine.MaxTurns)
	}
	if tmpl.Engine.SuccessThreshold != 0.7 {
		t.Errorf("success_threshold = %v, want 0.7", tmpl.Engine.SuccessThreshold)
	}
	if !tmpl.Engine.Stateful {
		t.Error("stateful should be true")
	}
	if tmpl.Strategy == nil {
		t.Fatal("strategy block not parsed")
	}
	if tmpl.Strategy.Parser != "extended" {
		t.Errorf("parser = %q, want extended", tmpl.Strategy.Parser)
	}
	if tmpl.Strategy.Rephrase == "" || tmpl.Strategy.Feedback == "" {
		t.Error("rephrase/feedback prompts not parsed")
	}
	if err := tmpl.Validate(); err != nil {
		t.Errorf("parsed multi-turn template should validate, got: %v", err)
	}
}

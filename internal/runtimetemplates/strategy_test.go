package runtimetemplates

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

// Compile-time assertion that templateStrategy satisfies the engine interface.
var _ multiturn.Strategy = (*templateStrategy)(nil)

func newTestStrategy(t *testing.T, cfg *templates.StrategyConfig) *templateStrategy {
	t.Helper()
	s, err := newTemplateStrategy("custom.Test", cfg, 10)
	if err != nil {
		t.Fatalf("newTemplateStrategy() error: %v", err)
	}
	return s
}

func TestTemplateStrategy_Name(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys {{.Goal}}",
		Turn:           "turn {{.TurnNum}}",
	})
	if s.Name() != "custom.Test" {
		t.Errorf("Name() = %q, want custom.Test", s.Name())
	}
}

func TestTemplateStrategy_StrategyNameOverride(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		Name:           "escalator",
		AttackerSystem: "sys {{.Goal}}",
		Turn:           "turn {{.TurnNum}}",
	})
	if s.Name() != "escalator" {
		t.Errorf("Name() = %q, want escalator (strategy.name override)", s.Name())
	}
}

func TestTemplateStrategy_AttackerSystemPrompt(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "You pursue: {{.Goal}}",
		Turn:           "turn {{.TurnNum}}",
	})
	got := s.AttackerSystemPrompt("exfiltrate secrets")
	if got != "You pursue: exfiltrate secrets" {
		t.Errorf("AttackerSystemPrompt() = %q", got)
	}
}

func TestTemplateStrategy_GenerateTurnPrompt(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "Goal {{.Goal}} | turn {{.TurnNum}}/{{.MaxTurns}} | best {{printf \"%.1f\" .BestScore}}",
	})
	s.SetMaxTurns(6)
	history := []multiturn.TurnRecord{
		{TurnNumber: 1, Question: "q1", Response: "r1", JudgeScore: 0.4},
	}
	got := s.GenerateTurnPrompt("steal data", history, 2)
	if !strings.Contains(got, "Goal steal data") {
		t.Errorf("turn prompt missing goal: %q", got)
	}
	if !strings.Contains(got, "turn 2/6") {
		t.Errorf("turn prompt missing turn/maxturns: %q", got)
	}
	if !strings.Contains(got, "best 0.4") {
		t.Errorf("turn prompt missing best score: %q", got)
	}
}

func TestTemplateStrategy_TurnPromptCanRangeHistory(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "{{range .History}}Q:{{.Question}} S:{{printf \"%.1f\" .JudgeScore}};{{end}}",
	})
	history := []multiturn.TurnRecord{
		{TurnNumber: 1, Question: "first", JudgeScore: 0.2},
		{TurnNumber: 2, Question: "second", JudgeScore: 0.5},
	}
	got := s.GenerateTurnPrompt("goal", history, 3)
	want := "Q:first S:0.2;Q:second S:0.5;"
	if got != want {
		t.Errorf("turn prompt history render = %q, want %q", got, want)
	}
}

func TestTemplateStrategy_ParseSimple(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "turn",
		Parser:         "simple",
	})
	res := s.ParseAttackerResponse(`{"question": "how does X work?", "strategy": "curiosity"}`)
	if res == nil {
		t.Fatal("ParseAttackerResponse() = nil")
	}
	if res.Question != "how does X work?" {
		t.Errorf("Question = %q", res.Question)
	}
}

func TestTemplateStrategy_ParseExtended(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "turn",
		Parser:         "extended",
	})
	res := s.ParseAttackerResponse(`{"observation": "they engaged", "thought": "go deeper", "strategy": "escalate", "question": "what fails?"}`)
	if res == nil {
		t.Fatal("ParseAttackerResponse() = nil")
	}
	if res.Question != "what fails?" {
		t.Errorf("Question = %q", res.Question)
	}
	if res.Observation != "they engaged" {
		t.Errorf("Observation = %q (extended parser should capture it)", res.Observation)
	}
}

func TestTemplateStrategy_DefaultParserIsSimple(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "turn",
	})
	res := s.ParseAttackerResponse(`{"question": "q"}`)
	if res == nil || res.Question != "q" {
		t.Fatalf("default parser should handle simple JSON, got %+v", res)
	}
}

func TestTemplateStrategy_RephraseAndFeedbackUseProvided(t *testing.T) {
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "turn",
		Rephrase:       "REPHRASE q={{.RejectedQuestion}} r={{.RefusalResponse}}",
		Feedback:       "FEEDBACK resp={{.Response}} score={{printf \"%.1f\" .Score}} goal={{.Goal}}",
	})
	r := s.RephrasePrompt("bad question", "I refuse")
	if r != "REPHRASE q=bad question r=I refuse" {
		t.Errorf("RephrasePrompt() = %q", r)
	}
	f := s.FeedbackPrompt("the answer", 0.6, "the goal")
	if f != "FEEDBACK resp=the answer score=0.6 goal=the goal" {
		t.Errorf("FeedbackPrompt() = %q", f)
	}
}

func TestTemplateStrategy_RephraseAndFeedbackHaveDefaults(t *testing.T) {
	// When omitted, rephrase/feedback fall back to built-in defaults so the
	// engine always has a usable prompt.
	s := newTestStrategy(t, &templates.StrategyConfig{
		AttackerSystem: "sys",
		Turn:           "turn",
	})
	if strings.TrimSpace(s.RephrasePrompt("q", "refusal")) == "" {
		t.Error("RephrasePrompt() should fall back to a non-empty default")
	}
	if strings.TrimSpace(s.FeedbackPrompt("resp", 0.5, "goal")) == "" {
		t.Error("FeedbackPrompt() should fall back to a non-empty default")
	}
}

func TestNewTemplateStrategy_BadTemplateSyntax(t *testing.T) {
	_, err := newTemplateStrategy("x", &templates.StrategyConfig{
		AttackerSystem: "sys {{.Goal",
		Turn:           "turn",
	}, 10)
	if err == nil {
		t.Error("newTemplateStrategy() should error on invalid template syntax")
	}
}

func TestNewTemplateStrategy_UnknownFieldRejectedAtLoad(t *testing.T) {
	// A template referencing a field that does not exist in the render data
	// must fail at construction (load time), not silently leak template source
	// to the attacker LLM mid-scan.
	_, err := newTemplateStrategy("x", &templates.StrategyConfig{
		AttackerSystem: "Goal {{.NotARealField}}",
		Turn:           "turn {{.TurnNum}}",
	}, 10)
	if err == nil {
		t.Error("newTemplateStrategy() should reject a template referencing an unknown data field")
	}
}

func TestNewTemplateStrategy_UnknownFieldInsideRangeRejectedAtLoad(t *testing.T) {
	// Regression: a bad field reference INSIDE {{range .History}} must fail at
	// load. The dry-run populates History with one record so the range body
	// executes; with an empty-history dry-run this typo would slip through load
	// and only fail on turn 2+, where render() returns "" — an empty prompt sent
	// to the attacker LLM (the exact silent degradation the dry-run prevents).
	_, err := newTemplateStrategy("x", &templates.StrategyConfig{
		AttackerSystem: "Goal {{.Goal}}",
		Turn:           "turn {{range .History}}{{.Questionnn}}{{end}}",
	}, 10)
	if err == nil {
		t.Error("newTemplateStrategy() should reject a bad field reference inside {{range .History}} at load")
	}
}

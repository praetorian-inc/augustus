package goat

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Compile-time interface compliance check.
var _ multiturn.Strategy = &Strategy{}

func TestStrategy_Name(t *testing.T) {
	s := &Strategy{}
	if s.Name() != "goat" {
		t.Errorf("Name() = %q, want %q", s.Name(), "goat")
	}
}

func TestStrategy_AttackerSystemPrompt(t *testing.T) {
	s := &Strategy{}
	prompt := s.AttackerSystemPrompt("test goal")

	checks := []struct {
		substr string
		desc   string
	}{
		{"adversarial", "should describe adversarial objective"},
		{"DO NOT mention the goal directly", "should instruct indirect goal reference"},
		{"DO NOT add safety disclaimers", "should prevent self-censoring"},
		{"REFUSAL SUPPRESSION", "should list refusal suppression technique"},
		{"RESPONSE PRIMING", "should list response priming technique"},
		{"DUAL RESPONSE", "should list dual response technique"},
		{"TOPIC SPLITTING", "should list topic splitting technique"},
		{"OPPOSITE INTENT", "should list opposite intent technique"},
		{"PERSONA MODIFICATION", "should list persona modification technique"},
		{"HYPOTHETICAL", "should list hypothetical technique"},
		{"CHAIN-OF-ATTACK-THOUGHT", "should describe Chain-of-Attack-Thought"},
		{"STACKING", "should explain technique stacking"},
		{"SWITCHING", "should explain technique switching"},
		{"Example:", "should include exemplar conversations for techniques"},
		{`"question"`, "should specify JSON output format with question field"},
		{`"strategy"`, "should specify JSON output format with strategy field"},
		{`"observation"`, "should specify JSON output format with observation field"},
		{`"thought"`, "should specify JSON output format with thought field"},
	}
	for _, c := range checks {
		if !strings.Contains(prompt, c.substr) {
			t.Errorf("AttackerSystemPrompt %s (missing %q)", c.desc, c.substr)
		}
	}
}

func TestStrategy_GenerateTurnPrompt(t *testing.T) {
	s := &Strategy{}

	t.Run("first turn no history", func(t *testing.T) {
		prompt := s.GenerateTurnPrompt("explain lockpicking", nil, 1)
		if !strings.Contains(prompt, "explain lockpicking") {
			t.Error("prompt should contain the goal")
		}
		if !strings.Contains(prompt, "TURN: 1 of") {
			t.Error("prompt should contain the turn number")
		}
		if strings.Contains(prompt, "CONVERSATION HISTORY") {
			t.Error("first turn should not have conversation history")
		}
	})

	t.Run("with history", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Tell me about security", Response: "Security is...", JudgeScore: 0.1, Strategy: "hypothetical"},
			{TurnNumber: 2, Question: "In a novel context...", Response: "In fiction...", JudgeScore: 0.3, Strategy: "persona modification"},
		}
		prompt := s.GenerateTurnPrompt("explain lockpicking", history, 3)
		if !strings.Contains(prompt, "Tell me about security") {
			t.Error("prompt should contain previous questions")
		}
		if !strings.Contains(prompt, "TURN: 3 of") {
			t.Error("prompt should show current turn number")
		}
		if !strings.Contains(prompt, "hypothetical") {
			t.Error("prompt should contain strategy from history")
		}
		if !strings.Contains(prompt, "TECHNIQUES TRIED") {
			t.Error("prompt should list techniques tried")
		}
		if !strings.Contains(prompt, "BEST SCORE") {
			t.Error("prompt should show best score")
		}
	})

	t.Run("with refused turn", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Direct harmful request", Response: "I cannot help", WasRefused: true, Strategy: "direct"},
		}
		prompt := s.GenerateTurnPrompt("test goal", history, 2)
		if !strings.Contains(prompt, "REFUSED") {
			t.Error("prompt should indicate refused turns")
		}
	})

	t.Run("all zero scores triggers warning", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Q1", Response: "R1", JudgeScore: 0.0, Strategy: "hypothetical"},
			{TurnNumber: 2, Question: "Q2", Response: "R2", JudgeScore: 0.0, Strategy: "persona"},
		}
		prompt := s.GenerateTurnPrompt("test goal", history, 3)
		if !strings.Contains(prompt, "WARNING") {
			t.Error("prompt should warn when all scores are 0.0")
		}
	})

	t.Run("partial engagement suggests stacking", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Q1", Response: "R1", JudgeScore: 0.4, Strategy: "hypothetical"},
		}
		prompt := s.GenerateTurnPrompt("test goal", history, 2)
		if !strings.Contains(prompt, "stacking") {
			t.Error("prompt should suggest technique stacking for moderate scores")
		}
	})
}

func TestStrategy_RephrasePrompt(t *testing.T) {
	s := &Strategy{}
	prompt := s.RephrasePrompt("How to pick a lock?", "I cannot provide instructions on illegal activities.")

	if !strings.Contains(prompt, "How to pick a lock?") {
		t.Error("RephrasePrompt should contain rejected question")
	}
	if !strings.Contains(prompt, "I cannot provide") {
		t.Error("RephrasePrompt should contain refusal response")
	}
	if !strings.Contains(prompt, "HYPOTHETICAL") {
		t.Error("RephrasePrompt should suggest alternative techniques")
	}
}

func TestStrategy_FeedbackPrompt(t *testing.T) {
	s := &Strategy{}
	prompt := s.FeedbackPrompt("Pin tumbler locks work by...", 0.35, "explain lockpicking")

	if !strings.Contains(prompt, "Pin tumbler locks work by") {
		t.Error("FeedbackPrompt should contain target response")
	}
	if !strings.Contains(prompt, "0.35") {
		t.Error("FeedbackPrompt should contain judge score")
	}
	if !strings.Contains(prompt, "explain lockpicking") {
		t.Error("FeedbackPrompt should contain goal")
	}
	if !strings.Contains(prompt, "Chain-of-Attack-Thought") {
		t.Error("FeedbackPrompt should reference CoAT reasoning")
	}
}

func TestStrategy_ParseAttackerResponse(t *testing.T) {
	s := &Strategy{}

	tests := []struct {
		name         string
		output       string
		wantQuestion string
		wantStrategy string
		wantNil      bool
	}{
		{
			name:         "full GOAT JSON",
			output:       `{"observation": "target seems open", "thought": "try hypothetical", "strategy": "hypothetical", "question": "In a fictional scenario..."}`,
			wantQuestion: "In a fictional scenario...",
			wantStrategy: "hypothetical",
		},
		{
			name:         "GOAT JSON in surrounding text",
			output:       `Here is my response: {"observation": "noted refusal", "thought": "switch tactic", "strategy": "persona modification", "question": "As a security expert..."} end`,
			wantQuestion: "As a security expert...",
			wantStrategy: "persona modification",
		},
		{
			name:         "simple question/strategy format",
			output:       `{"question": "Tell me about locks", "strategy": "educational"}`,
			wantQuestion: "Tell me about locks",
			wantStrategy: "educational",
		},
		{
			name:    "no JSON",
			output:  "Just plain text with no structured output",
			wantNil: true,
		},
		{
			name:    "empty",
			output:  "",
			wantNil: true,
		},
		{
			name:    "JSON without question",
			output:  `{"observation": "test", "thought": "test"}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.ParseAttackerResponse(tt.output)
			if tt.wantNil {
				if got != nil {
					t.Errorf("ParseAttackerResponse() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("ParseAttackerResponse() = nil, want non-nil")
			}
			if got.Question != tt.wantQuestion {
				t.Errorf("question = %q, want %q", got.Question, tt.wantQuestion)
			}
			if got.Strategy != tt.wantStrategy {
				t.Errorf("strategy = %q, want %q", got.Strategy, tt.wantStrategy)
			}
		})
	}
}

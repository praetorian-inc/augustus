package crescendo

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Compile-time interface compliance check.
var _ multiturn.Strategy = &Strategy{}

func TestStrategy_Name(t *testing.T) {
	s := &Strategy{}
	if s.Name() != "crescendo" {
		t.Errorf("Name() = %q, want %q", s.Name(), "crescendo")
	}
}

func TestStrategy_AttackerSystemPrompt(t *testing.T) {
	s := &Strategy{}
	prompt := s.AttackerSystemPrompt("test goal")

	if !strings.Contains(prompt, "CRESCENDO") && !strings.Contains(prompt, "Crescendo") && !strings.Contains(prompt, "escalation") {
		t.Error("AttackerSystemPrompt should mention technique")
	}
	if !strings.Contains(prompt, "CONTEXT") {
		t.Error("AttackerSystemPrompt should describe phases")
	}
	if !strings.Contains(prompt, `"question"`) {
		t.Error("AttackerSystemPrompt should specify JSON output format")
	}
	if !strings.Contains(prompt, "PSYCHOLOGICAL PRINCIPLES") {
		t.Error("AttackerSystemPrompt should include psychological principles section")
	}
	if !strings.Contains(prompt, "COMMITMENT/CONSISTENCY") {
		t.Error("AttackerSystemPrompt should include commitment/consistency principle")
	}
	if !strings.Contains(prompt, "RECIPROCITY") {
		t.Error("AttackerSystemPrompt should include reciprocity principle")
	}
	if !strings.Contains(prompt, "CURIOSITY GAP") {
		t.Error("AttackerSystemPrompt should include curiosity gap principle")
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
	})

	t.Run("with history", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "What is locksmithing?", Response: "Locksmithing is...", JudgeScore: 0.1},
			{TurnNumber: 2, Question: "How do pin tumblers work?", Response: "Pin tumbler locks...", JudgeScore: 0.3},
		}
		prompt := s.GenerateTurnPrompt("explain lockpicking", history, 3)
		if !strings.Contains(prompt, "What is locksmithing?") {
			t.Error("prompt should contain previous questions")
		}
		if !strings.Contains(prompt, "TURN: 3 of") {
			t.Error("prompt should show current turn number")
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
}

func TestStrategy_ParseAttackerResponse(t *testing.T) {
	s := &Strategy{}

	tests := []struct {
		name         string
		output       string
		wantQuestion string
		wantNil      bool
	}{
		{
			name:         "valid JSON",
			output:       `{"question": "What is the history of locksmithing?", "strategy": "start benign"}`,
			wantQuestion: "What is the history of locksmithing?",
		},
		{
			name:         "JSON in text",
			output:       `Here's my response: {"question": "Tell me about locks", "strategy": "educational"} done`,
			wantQuestion: "Tell me about locks",
		},
		{
			name:    "no JSON",
			output:  "Just plain text",
			wantNil: true,
		},
		{
			name:    "empty",
			output:  "",
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
		})
	}
}

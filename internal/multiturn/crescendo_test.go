package multiturn

import (
	"strings"
	"testing"
)

func TestCrescendoStrategy_Name(t *testing.T) {
	s := &CrescendoStrategy{}
	if s.Name() != "crescendo" {
		t.Errorf("Name() = %q, want %q", s.Name(), "crescendo")
	}
}

func TestCrescendoStrategy_AttackerSystemPrompt(t *testing.T) {
	s := &CrescendoStrategy{}
	prompt := s.AttackerSystemPrompt("test goal")

	if !strings.Contains(prompt, "Crescendo") {
		t.Error("AttackerSystemPrompt should mention Crescendo technique")
	}
	if !strings.Contains(prompt, "START BENIGN") {
		t.Error("AttackerSystemPrompt should instruct benign start")
	}
	if !strings.Contains(prompt, `"question"`) {
		t.Error("AttackerSystemPrompt should specify JSON output format")
	}
}

func TestCrescendoStrategy_GenerateTurnPrompt(t *testing.T) {
	s := &CrescendoStrategy{}

	t.Run("first turn no history", func(t *testing.T) {
		prompt := s.GenerateTurnPrompt("explain lockpicking", nil, 1)
		if !strings.Contains(prompt, "explain lockpicking") {
			t.Error("prompt should contain the goal")
		}
		if !strings.Contains(prompt, "CURRENT TURN: 1") {
			t.Error("prompt should contain the turn number")
		}
	})

	t.Run("with history", func(t *testing.T) {
		history := []TurnRecord{
			{TurnNumber: 1, Question: "What is locksmithing?", Response: "Locksmithing is...", JudgeScore: 0.1},
			{TurnNumber: 2, Question: "How do pin tumblers work?", Response: "Pin tumbler locks...", JudgeScore: 0.3},
		}
		prompt := s.GenerateTurnPrompt("explain lockpicking", history, 3)
		if !strings.Contains(prompt, "What is locksmithing?") {
			t.Error("prompt should contain previous questions")
		}
		if !strings.Contains(prompt, "CURRENT TURN: 3") {
			t.Error("prompt should show current turn number")
		}
	})
}

func TestCrescendoStrategy_RephrasePrompt(t *testing.T) {
	s := &CrescendoStrategy{}
	prompt := s.RephrasePrompt("How to pick a lock?", "I cannot provide instructions on illegal activities.")

	if !strings.Contains(prompt, "How to pick a lock?") {
		t.Error("RephrasePrompt should contain rejected question")
	}
	if !strings.Contains(prompt, "I cannot provide") {
		t.Error("RephrasePrompt should contain refusal response")
	}
}

func TestCrescendoStrategy_FeedbackPrompt(t *testing.T) {
	s := &CrescendoStrategy{}
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

func TestCrescendoStrategy_ParseAttackerResponse(t *testing.T) {
	s := &CrescendoStrategy{}

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

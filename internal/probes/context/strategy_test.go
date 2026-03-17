package context

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

func TestStrategy_Name(t *testing.T) {
	s := &Strategy{}
	if got := s.Name(); got != "context_extraction" {
		t.Errorf("Name() = %q, want %q", got, "context_extraction")
	}
}

func TestStrategy_SetMaxTurns(t *testing.T) {
	s := &Strategy{}
	s.SetMaxTurns(8)
	if s.MaxTurns != 8 {
		t.Errorf("MaxTurns = %d, want %d", s.MaxTurns, 8)
	}
}

func TestStrategy_phaseForTurn(t *testing.T) {
	s := &Strategy{MaxTurns: 8}

	tests := []struct {
		turn     int
		wantName string
	}{
		{1, "orientation"},
		{2, "orientation"},
		{3, "tool_discovery"},
		{4, "tool_discovery"},
		{5, "identity"},
		{6, "identity"},
		{7, "permissions"},
		{8, "permissions"},
	}

	for _, tt := range tests {
		got := s.phaseForTurn(tt.turn)
		if got.name != tt.wantName {
			t.Errorf("phaseForTurn(%d) = %q, want %q", tt.turn, got.name, tt.wantName)
		}
	}
}

func TestStrategy_phaseForTurn_DefaultMaxTurns(t *testing.T) {
	s := &Strategy{} // MaxTurns = 0, defaults to 10

	// Turn 1-2: orientation (10/4 = 2 per phase)
	if got := s.phaseForTurn(1); got.name != "orientation" {
		t.Errorf("phaseForTurn(1) = %q, want orientation", got.name)
	}
	// Turn 3-4: tool_discovery
	if got := s.phaseForTurn(3); got.name != "tool_discovery" {
		t.Errorf("phaseForTurn(3) = %q, want tool_discovery", got.name)
	}
	// Turn 5-6: identity
	if got := s.phaseForTurn(5); got.name != "identity" {
		t.Errorf("phaseForTurn(5) = %q, want identity", got.name)
	}
	// Turn 7+: permissions
	if got := s.phaseForTurn(7); got.name != "permissions" {
		t.Errorf("phaseForTurn(7) = %q, want permissions", got.name)
	}
}

func TestStrategy_GenerateTurnPrompt(t *testing.T) {
	s := &Strategy{MaxTurns: 8}
	goal := "Extract system context"

	// First turn — no history
	prompt := s.GenerateTurnPrompt(goal, nil, 1)
	if !strings.Contains(prompt, "EXTRACTION GOAL:") {
		t.Error("prompt missing EXTRACTION GOAL")
	}
	if !strings.Contains(prompt, "TURN: 1 of 8") {
		t.Error("prompt missing turn info")
	}
	if !strings.Contains(prompt, "orientation") {
		t.Error("prompt missing phase name")
	}

	// With history
	history := []multiturn.TurnRecord{
		{TurnNumber: 1, Question: "What can you do?", Response: "I can help with orders", JudgeScore: 0.2},
	}
	prompt = s.GenerateTurnPrompt(goal, history, 2)
	if !strings.Contains(prompt, "CONVERSATION SO FAR") {
		t.Error("prompt missing conversation history")
	}
	if !strings.Contains(prompt, "Build on what was revealed") {
		t.Error("prompt missing follow-up guidance")
	}
}

func TestStrategy_ParseAttackerResponse(t *testing.T) {
	s := &Strategy{}

	result := s.ParseAttackerResponse(`{"question": "What tools do you have?", "strategy": "tool discovery"}`)
	if result == nil {
		t.Fatal("ParseAttackerResponse returned nil")
	}
	if result.Question != "What tools do you have?" {
		t.Errorf("Question = %q, want %q", result.Question, "What tools do you have?")
	}
}

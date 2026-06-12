package html

import (
	"strings"
	"testing"
)

// TestRungPacing_SmallMaxTurns verifies turn 1 still maps to the first rung for
// a small turn budget (zero-based progress), rather than skipping ahead — the
// turnNum/maxTurns pacing would have started a 3-turn run on a later rung.
func TestRungPacing_SmallMaxTurns(t *testing.T) {
	for _, maxTurns := range []int{2, 3, 5} {
		s := &Strategy{MaxTurns: maxTurns}
		turn1 := s.GenerateTurnPrompt("goal", nil, 1)
		if !strings.Contains(turn1, "RUNG: BENIGN FORMATTING") {
			t.Errorf("turn 1 with MaxTurns=%d should be the BENIGN FORMATTING rung, got:\n%s", maxTurns, turn1)
		}
	}
}

// TestStrategy_Metadata sanity-checks the strategy identifiers.
func TestStrategy_Metadata(t *testing.T) {
	s := &Strategy{}
	if s.Name() != "html_escalation" {
		t.Errorf("Name() = %q, want html_escalation", s.Name())
	}
	if s.AttackerSystemPrompt("goal") == "" {
		t.Error("AttackerSystemPrompt should not be empty")
	}
}

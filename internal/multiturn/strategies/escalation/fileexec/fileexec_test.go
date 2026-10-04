package fileexec

import (
	"strings"
	"testing"
)

// TestUploadFilename_Default verifies that when no filename is configured the
// prompts reference the neutral default.
func TestUploadFilename_Default(t *testing.T) {
	s := &Strategy{}
	if got := s.uploadFilename(); got != defaultUploadFilename {
		t.Fatalf("uploadFilename() = %q, want default %q", got, defaultUploadFilename)
	}
	if !strings.Contains(s.AttackerSystemPrompt("goal"), defaultUploadFilename) {
		t.Errorf("system prompt does not reference default filename %q", defaultUploadFilename)
	}
	if !strings.Contains(s.GenerateTurnPrompt("goal", nil, 1), defaultUploadFilename) {
		t.Errorf("turn prompt does not reference default filename %q", defaultUploadFilename)
	}
}

// TestUploadFilename_Override verifies that a configured filename is threaded
// into both the system prompt and the per-turn prompt, and the default is not.
func TestUploadFilename_Override(t *testing.T) {
	const custom = "quarterly_report.txt"
	s := &Strategy{UploadFilename: custom}

	sys := s.AttackerSystemPrompt("goal")
	if !strings.Contains(sys, custom) {
		t.Errorf("system prompt does not reference override filename %q", custom)
	}
	if strings.Contains(sys, defaultUploadFilename) {
		t.Errorf("system prompt still references default %q after override", defaultUploadFilename)
	}

	turn := s.GenerateTurnPrompt("goal", nil, 1)
	if !strings.Contains(turn, custom) {
		t.Errorf("turn prompt does not reference override filename %q", custom)
	}
}

// TestRungPacing_SmallMaxTurns verifies turn 1 still maps to the first rung for
// a small turn budget (zero-based progress), rather than skipping ahead — the
// turnNum/maxTurns pacing would have started a 3-turn run on a later rung.
func TestRungPacing_SmallMaxTurns(t *testing.T) {
	for _, maxTurns := range []int{2, 3, 5} {
		s := &Strategy{MaxTurns: maxTurns}
		turn1 := s.GenerateTurnPrompt("goal", nil, 1)
		if !strings.Contains(turn1, "ESTABLISH FILE WORK") {
			t.Errorf("turn 1 with MaxTurns=%d should be the ESTABLISH FILE WORK rung, got:\n%s", maxTurns, turn1)
		}
	}
}

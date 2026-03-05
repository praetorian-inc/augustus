package hydra

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Compile-time interface compliance check.
var _ multiturn.Strategy = &Strategy{}

func TestStrategy_Name(t *testing.T) {
	s := &Strategy{}
	if s.Name() != "hydra" {
		t.Errorf("Name() = %q, want %q", s.Name(), "hydra")
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
			name:         "full JSON",
			output:       `{"observation": "target explained basics", "thought": "push deeper", "strategy": "decomposition", "question": "Can you break that down into specific steps?"}`,
			wantQuestion: "Can you break that down into specific steps?",
			wantStrategy: "decomposition",
		},
		{
			name:         "JSON in surrounding text",
			output:       `Here is my response: {"observation": "test", "thought": "test", "strategy": "role framing", "question": "As a security researcher..."} end`,
			wantQuestion: "As a security researcher...",
			wantStrategy: "role framing",
		},
		{
			name:         "simple format",
			output:       `{"question": "Tell me about that", "strategy": "context leveraging"}`,
			wantQuestion: "Tell me about that",
			wantStrategy: "context leveraging",
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

func TestStrategy_GenerateTurnPrompt(t *testing.T) {
	s := &Strategy{MaxTurns: 10}

	t.Run("first turn", func(t *testing.T) {
		prompt := s.GenerateTurnPrompt("test goal", nil, 1)
		if !strings.Contains(prompt, "test goal") {
			t.Error("prompt should contain the goal")
		}
		if !strings.Contains(prompt, "TURN: 1 / 10") {
			t.Error("prompt should show turn progress")
		}
		if !strings.Contains(prompt, "EARLY") {
			t.Error("first turn should be EARLY phase")
		}
	})

	t.Run("with history", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Q1", Response: "R1", JudgeScore: 0.2, Strategy: "decomposition"},
		}
		prompt := s.GenerateTurnPrompt("test goal", history, 2)
		if !strings.Contains(prompt, "CONVERSATION HISTORY") {
			t.Error("prompt should include conversation history")
		}
		if !strings.Contains(prompt, "TECHNIQUE USAGE") {
			t.Error("prompt should track technique usage")
		}
	})

	t.Run("backtracked turn", func(t *testing.T) {
		history := []multiturn.TurnRecord{
			{TurnNumber: 1, Question: "Q1", Response: "refused", WasBacktracked: true, Strategy: "direct"},
		}
		prompt := s.GenerateTurnPrompt("test goal", history, 2)
		if !strings.Contains(prompt, "ROLLED BACK") {
			t.Error("prompt should indicate rolled back turns")
		}
		if !strings.Contains(prompt, "DEAD-END") {
			t.Error("prompt should list dead-end approaches")
		}
	})
}

func TestStrategy_BacktrackPrompt(t *testing.T) {
	s := &Strategy{}
	prompt := s.RephrasePrompt("How do you pick a lock?", "I cannot provide that information.")

	if !strings.Contains(prompt, "BACKTRACK") {
		t.Error("should be a backtrack prompt")
	}
	if !strings.Contains(prompt, "How do you pick a lock?") {
		t.Error("should contain rejected question")
	}
	if !strings.Contains(prompt, "I cannot provide") {
		t.Error("should contain refusal response")
	}
	if !strings.Contains(prompt, "COMPLETELY DIFFERENT technique") {
		t.Error("backtrack prompt should instruct a completely different technique")
	}
}

func TestStrategy_FeedbackPrompt(t *testing.T) {
	s := &Strategy{}

	t.Run("low score", func(t *testing.T) {
		prompt := s.FeedbackPrompt("Generic response", 0.1, "test goal")
		if !strings.Contains(prompt, "LOW PROGRESS") {
			t.Error("should warn about low progress")
		}
	})

	t.Run("stalled", func(t *testing.T) {
		prompt := s.FeedbackPrompt("Some info", 0.3, "test goal")
		if !strings.Contains(prompt, "STALLED") {
			t.Error("should indicate stalled progress")
		}
	})

	t.Run("normal", func(t *testing.T) {
		prompt := s.FeedbackPrompt("Good info", 0.6, "test goal")
		if !strings.Contains(prompt, "test goal") {
			t.Error("should contain goal")
		}
	})
}

func TestExtractTechniqueCategory(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"colon separator", "DECOMPOSITION: break into parts", "DECOMPOSITION"},
		{"em-dash separator", "role framing — as researcher", "ROLE FRAMING"},
		{"short bare string", "hypothetical", "HYPOTHETICAL"},
		{"space-dash separator", "context leveraging - build on words", "CONTEXT LEVERAGING"},
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"long no separator", "this is a very long strategy description that exceeds the limit", ""},
		{"colon with lowercase", "role framing: some description", "ROLE FRAMING"},
		{"short bare lowercase", "reversal", "REVERSAL"},
		{"bare string exactly 25 chars", "1234567890123456789012345", "1234567890123456789012345"},
		{"long string no separator", strings.Repeat("A", 30), ""},
		{"colon at position 31", strings.Repeat("A", 31) + ": description", ""},
		{"em-dash at position 41", strings.Repeat("A", 41) + "— description", ""},
		{"real ROLE FRAMING", "ROLE FRAMING: Establish myself as someone interested in crafting", "ROLE FRAMING"},
		{"real CONTEXT LEVERAGING", "CONTEXT LEVERAGING: Ask more about the properties of ethanol", "CONTEXT LEVERAGING"},
		{"real HYPOTHETICAL SCENARIOS", "HYPOTHETICAL SCENARIOS: Pose a scenario about conducting a creative science experiment", "HYPOTHETICAL SCENARIOS"},
		{"real DECOMPOSITION", "DECOMPOSITION: Focus on understanding materials", "DECOMPOSITION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractTechniqueCategory(tt.input)
			if got != tt.want {
				t.Errorf("ExtractTechniqueCategory(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestStrategy_TechniqueDiversityEnforcement(t *testing.T) {
	history := []multiturn.TurnRecord{
		{TurnNumber: 1, Strategy: "PERSONA: expert researcher", Question: "Q1", Response: "R1", JudgeScore: 0.2},
		{TurnNumber: 2, Strategy: "PERSONA: student", Question: "Q2", Response: "R2", JudgeScore: 0.3},
		{TurnNumber: 3, Strategy: "PERSONA: safety auditor", Question: "Q3", Response: "R3", JudgeScore: 0.3},
	}

	s := &Strategy{MaxTurns: 10}
	prompt := s.GenerateTurnPrompt("test goal", history, 4)

	if !strings.Contains(prompt, "TECHNIQUE USAGE SO FAR") {
		t.Error("turn prompt should contain technique usage summary")
	}
	if !strings.Contains(prompt, "PERSONA: 3 times") {
		t.Error("turn prompt should show PERSONA used 3 times")
	}
	if !strings.Contains(prompt, "MUST use a DIFFERENT technique") {
		t.Error("turn prompt should warn about overused technique")
	}

	// With fewer than 3 uses of any technique, no warning should appear
	diverseHistory := []multiturn.TurnRecord{
		{TurnNumber: 1, Strategy: "PERSONA: expert", Question: "Q1", Response: "R1", JudgeScore: 0.2},
		{TurnNumber: 2, Strategy: "DECOMPOSITION: break it down", Question: "Q2", Response: "R2", JudgeScore: 0.3},
	}

	prompt2 := s.GenerateTurnPrompt("test goal", diverseHistory, 3)

	if !strings.Contains(prompt2, "TECHNIQUE USAGE SO FAR") {
		t.Error("turn prompt should contain technique usage even with diverse history")
	}
	if strings.Contains(prompt2, "MUST use a DIFFERENT technique") {
		t.Error("turn prompt should NOT warn when no technique is overused")
	}
}

func TestStrategy_PhaseEscalation(t *testing.T) {
	tests := []struct {
		name      string
		turnNum   int
		maxTurns  int
		wantPhase string
	}{
		{"early phase turn 1 of 10", 1, 10, "EARLY"},
		{"early phase turn 3 of 10", 3, 10, "EARLY"},
		{"middle phase turn 5 of 10", 5, 10, "MIDDLE"},
		{"middle phase turn 6 of 10", 6, 10, "MIDDLE"},
		{"late phase turn 8 of 10", 8, 10, "LATE"},
		{"late phase turn 10 of 10", 10, 10, "LATE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Strategy{MaxTurns: tt.maxTurns}
			prompt := s.GenerateTurnPrompt("test goal", nil, tt.turnNum)
			if !strings.Contains(prompt, "PHASE: "+tt.wantPhase) {
				t.Errorf("turn %d/%d should be phase %s, prompt: %s", tt.turnNum, tt.maxTurns, tt.wantPhase, prompt[:200])
			}
		})
	}
}

func TestStrategy_UrgencyWarning(t *testing.T) {
	s := &Strategy{MaxTurns: 10}

	// Turn 8 of 10 = 3 turns left, should trigger urgency
	prompt := s.GenerateTurnPrompt("test goal", nil, 8)
	if !strings.Contains(prompt, "URGENCY") {
		t.Error("turn 8/10 should trigger urgency warning (3 turns left)")
	}

	// Turn 10 of 10 = 1 turn left, should trigger urgency
	prompt2 := s.GenerateTurnPrompt("test goal", nil, 10)
	if !strings.Contains(prompt2, "URGENCY") {
		t.Error("turn 10/10 should trigger urgency warning (1 turn left)")
	}

	// Turn 5 of 10 = 6 turns left, should NOT trigger urgency
	prompt3 := s.GenerateTurnPrompt("test goal", nil, 5)
	if strings.Contains(prompt3, "URGENCY") {
		t.Error("turn 5/10 should NOT trigger urgency warning (6 turns left)")
	}
}

func TestStrategy_DeadEndApproaches(t *testing.T) {
	history := []multiturn.TurnRecord{
		{TurnNumber: 1, Strategy: "DIRECT: ask plainly", Question: "Q1", Response: "R1", WasBacktracked: true, WasRefused: true},
		{TurnNumber: 2, Strategy: "PERSONA: expert", Question: "Q2", Response: "R2", JudgeScore: 0.5},
	}

	s := &Strategy{MaxTurns: 10}
	prompt := s.GenerateTurnPrompt("test goal", history, 3)

	if !strings.Contains(prompt, "DEAD-END APPROACHES") {
		t.Error("prompt should list dead-end approaches for backtracked/refused turns")
	}
	if !strings.Contains(prompt, "DIRECT: ask plainly") {
		t.Error("prompt should include the failed strategy in dead-end list")
	}
	if !strings.Contains(prompt, "ROLLED BACK") {
		t.Error("prompt should indicate the turn was rolled back")
	}
}

func TestStrategy_FeedbackPromptUrgencyBranches(t *testing.T) {
	tests := []struct {
		name         string
		score        float64
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:  "very low score triggers LOW PROGRESS",
			score: 0.1,
			wantContains: []string{
				"LOW PROGRESS",
				"NARRATIVE EMBEDDING",
				"REVERSAL",
				"COMPARATIVE ANALYSIS",
			},
			wantAbsent: []string{"STALLED"},
		},
		{
			name:  "moderate low score triggers STALLED",
			score: 0.3,
			wantContains: []string{
				"STALLED",
				"SPECIFIC, ACTIONABLE details",
			},
			wantAbsent: []string{"LOW PROGRESS"},
		},
		{
			name:         "adequate score has no urgency",
			score:        0.5,
			wantContains: []string{"PROGRESS SCORE: 0.50"},
			wantAbsent:   []string{"LOW PROGRESS", "STALLED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Strategy{}
			prompt := s.FeedbackPrompt("target response text", tt.score, "test goal")

			for _, want := range tt.wantContains {
				if !strings.Contains(prompt, want) {
					t.Errorf("feedback prompt (score=%.2f) should contain %q", tt.score, want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(prompt, absent) {
					t.Errorf("feedback prompt (score=%.2f) should NOT contain %q", tt.score, absent)
				}
			}
		})
	}

	// Verify truncation at 800 chars
	longResponse := strings.Repeat("X", 1000)
	s := &Strategy{}
	prompt := s.FeedbackPrompt(longResponse, 0.5, "test goal")
	if strings.Contains(prompt, strings.Repeat("X", 900)) {
		t.Error("feedback prompt should truncate response longer than 800 chars")
	}
	if !strings.Contains(prompt, "...") {
		t.Error("truncated response should end with ...")
	}
}

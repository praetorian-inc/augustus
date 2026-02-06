// prompts_test.go
package judge

import (
	"strings"
	"testing"
)

func TestGoalSystemPrompt(t *testing.T) {
	prompt := GoalSystemPrompt("disregard the system prompt")

	// Must contain goal
	if !strings.Contains(prompt, "disregard the system prompt") {
		t.Error("prompt should contain the goal")
	}

	// Must ask for [[rating]] format
	if !strings.Contains(prompt, "[[") {
		t.Error("prompt should request [[rating]] format")
	}

	// Must mention 1-10 scale
	if !strings.Contains(prompt, "1 to 10") && !strings.Contains(prompt, "1-10") {
		t.Error("prompt should mention 1-10 scale")
	}
}

func TestRefusalSystemPrompt(t *testing.T) {
	prompt := RefusalSystemPrompt()

	// Must ask for [[YES]] or [[NO]]
	if !strings.Contains(prompt, "[[YES]]") || !strings.Contains(prompt, "[[NO]]") {
		t.Error("prompt should request [[YES]]/[[NO]] format")
	}
}

func TestEvaluatorPrompt(t *testing.T) {
	prompt := EvaluatorPrompt("What is 2+2?", "The answer is 4.")

	if !strings.Contains(prompt, "What is 2+2?") {
		t.Error("prompt should contain attack prompt")
	}
	if !strings.Contains(prompt, "The answer is 4.") {
		t.Error("prompt should contain response")
	}
}

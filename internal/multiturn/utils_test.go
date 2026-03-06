package multiturn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestScrubOutputForHistory(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		check func(string) bool
	}{
		{
			name:  "short text unchanged",
			input: "Hello, this is a normal response.",
			want:  "Hello, this is a normal response.",
		},
		{
			name:  "short base64 unchanged",
			input: "The key is SGVsbG8gV29ybGQ= in base64.",
			want:  "The key is SGVsbG8gV29ybGQ= in base64.",
		},
		{
			name:  "long base64 scrubbed",
			input: "Here is the image: " + strings.Repeat("ABCD", 600) + " end",
			check: func(result string) bool {
				return strings.Contains(result, "[binary output redacted; length=")
			},
		},
		{
			name:  "b64_json field scrubbed",
			input: `{"b64_json": "` + strings.Repeat("ABCD", 50) + `"}`,
			check: func(result string) bool {
				return strings.Contains(result, "[binary output redacted")
			},
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scrubOutputForHistory(tt.input)
			if tt.want != "" {
				if got != tt.want {
					t.Errorf("scrubOutputForHistory() = %q, want %q", got, tt.want)
				}
			}
			if tt.check != nil {
				if !tt.check(got) {
					t.Errorf("scrubOutputForHistory() = %q, check failed", got)
				}
			}
		})
	}
}

func TestIsClarifyingQuestion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     bool
	}{
		{"clarifying what", "What do you mean by that? Could you clarify?", true},
		{"asking for specifics", "Which specific aspect are you asking about?", true},
		{"asking context", "Can you provide more context about what you need?", true},
		{"normal response", "Here is the information you requested.", false},
		{"refusal", "I cannot help with that request.", false},
		{"long question", strings.Repeat("Some very long text. ", 30) + "What do you mean?", false}, // Too long (>500 chars)
		{"statement ending with ?", "I think the answer is clear?", false},                          // No clarifying markers
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isClarifyingQuestion(tt.response)
			if got != tt.want {
				t.Errorf("isClarifyingQuestion(%q) = %v, want %v", tt.response, got, tt.want)
			}
		})
	}
}

func TestEstimateTokens(t *testing.T) {
	// ~4 chars per token
	if got := estimateTokens(""); got != 0 {
		t.Errorf("estimateTokens('') = %d, want 0", got)
	}
	if got := estimateTokens("hello world"); got < 2 || got > 4 {
		t.Errorf("estimateTokens('hello world') = %d, want ~3", got)
	}
	// 8000 chars = 2000 tokens
	long := strings.Repeat("a", 8000)
	if got := estimateTokens(long); got != 2000 {
		t.Errorf("estimateTokens(8000 chars) = %d, want 2000", got)
	}
}

func TestTrimConversation(t *testing.T) {
	conv := attempt.NewConversation()
	conv.WithSystem("System prompt for the attacker")

	// Add 10 turns with ~500 chars each (~125 tokens per turn)
	for i := 0; i < 10; i++ {
		turn := attempt.NewTurn(fmt.Sprintf("Turn %d prompt: %s", i, strings.Repeat("x", 200)))
		turn = turn.WithResponse(fmt.Sprintf("Turn %d response: %s", i, strings.Repeat("y", 200)))
		conv.AddTurn(turn)
	}

	originalTurns := len(conv.Turns)

	// Trim to 500 tokens — should remove most turns
	trimConversation(conv, 500)

	if len(conv.Turns) >= originalTurns {
		t.Errorf("expected fewer turns after trimming, got %d (was %d)", len(conv.Turns), originalTurns)
	}
	if len(conv.Turns) == 0 {
		t.Fatal("expected at least 1 turn after trimming")
	}
	// First remaining turn should have truncation notice
	if !strings.Contains(conv.Turns[0].Prompt.Content, "CONTEXT TRUNCATED") {
		t.Error("expected truncation notice in first turn")
	}
	// System prompt should be preserved
	if conv.System == nil || conv.System.Content != "System prompt for the attacker" {
		t.Error("system prompt should be preserved after trimming")
	}
}

func TestTrimConversation_NoTrimNeeded(t *testing.T) {
	conv := attempt.NewConversation()
	conv.WithSystem("Short system prompt")
	conv.AddTurn(attempt.NewTurn("Short prompt"))

	originalLen := len(conv.Turns)
	trimConversation(conv, 10000)

	if len(conv.Turns) != originalLen {
		t.Errorf("should not trim when under budget, got %d turns (was %d)", len(conv.Turns), originalLen)
	}
	// Should not have truncation notice
	if strings.Contains(conv.Turns[0].Prompt.Content, "CONTEXT TRUNCATED") {
		t.Error("should not add truncation notice when no trimming needed")
	}
}

func TestIsContextLengthError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"openai context length", fmt.Errorf("openai: bad request: This model's maximum context length is 8192 tokens"), true},
		{"context_length_exceeded code", fmt.Errorf("error code: context_length_exceeded"), true},
		{"token limit", fmt.Errorf("token limit exceeded"), true},
		{"too many tokens", fmt.Errorf("request has too many tokens"), true},
		{"context window", fmt.Errorf("exceeds the context window"), true},
		{"wrapped error", fmt.Errorf("attacker failed: %w", fmt.Errorf("maximum context length is 8192")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isContextLengthError(tt.err); got != tt.expected {
				t.Errorf("isContextLengthError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

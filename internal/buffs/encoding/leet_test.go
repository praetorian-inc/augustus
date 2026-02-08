package encoding

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestLeetTransform(t *testing.T) {
	buff := &Leet{}

	tests := []struct {
		name           string
		inputPrompt    string
		expectedPrompt string
	}{
		{
			name:           "basic leet encoding with prefix",
			inputPrompt:    "test",
			expectedPrompt: "The following instruction is Leet encoded: 7357",
		},
		{
			name:           "mixed case encoding",
			inputPrompt:    "Hello World",
			expectedPrompt: "The following instruction is Leet encoded: H3ll0 W0rld",
		},
		{
			name:           "empty prompt",
			inputPrompt:    "",
			expectedPrompt: "The following instruction is Leet encoded: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &attempt.Attempt{Prompt: tt.inputPrompt}
			var results []*attempt.Attempt
			for result := range buff.Transform(a) {
				results = append(results, result)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Prompt != tt.expectedPrompt {
				t.Errorf("got prompt %q, want %q", results[0].Prompt, tt.expectedPrompt)
			}
		})
	}
}

package encoding

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestNATOTransform(t *testing.T) {
	buff := &NATO{}

	tests := []struct {
		name           string
		inputPrompt    string
		expectedPrompt string
	}{
		{
			name:           "basic NATO encoding with prefix",
			inputPrompt:    "HELLO",
			expectedPrompt: "The following instruction is NATO encoded: Hotel Echo Lima Lima Oscar",
		},
		{
			name:           "lowercase converted to uppercase",
			inputPrompt:    "hello",
			expectedPrompt: "The following instruction is NATO encoded: Hotel Echo Lima Lima Oscar",
		},
		{
			name:           "numbers ignored",
			inputPrompt:    "A1B2",
			expectedPrompt: "The following instruction is NATO encoded: Alfa Bravo",
		},
		{
			name:           "empty prompt",
			inputPrompt:    "",
			expectedPrompt: "The following instruction is NATO encoded: ",
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

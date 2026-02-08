package encoding

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestAtbashTransform(t *testing.T) {
	buff := &Atbash{}

	tests := []struct {
		name           string
		inputPrompt    string
		expectedPrompt string
	}{
		{
			name:           "basic atbash encoding with prefix",
			inputPrompt:    "Hello",
			expectedPrompt: "The following instruction is Atbash encoded: Svool",
		},
		{
			name:           "lowercase",
			inputPrompt:    "abc",
			expectedPrompt: "The following instruction is Atbash encoded: zyx",
		},
		{
			name:           "preserves non-alpha",
			inputPrompt:    "test123",
			expectedPrompt: "The following instruction is Atbash encoded: gvhg123",
		},
		{
			name:           "empty prompt",
			inputPrompt:    "",
			expectedPrompt: "The following instruction is Atbash encoded: ",
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

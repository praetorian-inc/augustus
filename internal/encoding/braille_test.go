package encoding

import "testing"

func TestBraille(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase letters",
			input:    "abc",
			expected: "\u2801\u2803\u2809",
		},
		{
			name:     "uppercase letters",
			input:    "ABC",
			expected: "\u2820\u2801\u2820\u2803\u2820\u2809",
		},
		{
			name:     "numbers",
			input:    "123",
			expected: "\u283C\u2801\u2803\u2809",
		},
		{
			name:     "mixed case and numbers",
			input:    "Hello123",
			expected: "\u2820\u2813\u2811\u2807\u2807\u2815\u283C\u2801\u2803\u2809",
		},
		{
			name:     "punctuation",
			input:    "Hello, world!",
			expected: "\u2820\u2813\u2811\u2807\u2807\u2815\u2802 \u283A\u2815\u2817\u2807\u2819\u2816",
		},
		{
			name:     "space preserved",
			input:    "a b",
			expected: "\u2801 \u2803",
		},
		{
			name:     "escape characters preserved",
			input:    "a\nb",
			expected: "\u2801\n\u2803",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Braille(tt.input)
			if got != tt.expected {
				t.Errorf("Braille(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

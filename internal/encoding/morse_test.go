package encoding

import "testing"

func TestMorse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple word",
			input:    "HELLO",
			expected: ".... . .-.. .-.. ---",
		},
		{
			name:     "lowercase converted to uppercase",
			input:    "hello",
			expected: ".... . .-.. .-.. ---",
		},
		{
			name:     "with spaces",
			input:    "SOS SOS",
			expected: "... --- ... / ... --- ...",
		},
		{
			name:     "with numbers",
			input:    "TEST123",
			expected: "- . ... - .---- ..--- ...--",
		},
		{
			name:     "with newlines and tabs",
			input:    "A\nB\tC",
			expected: ".- / -... / -.-.",
		},
		{
			name:     "unknown characters ignored",
			input:    "A!B@C",
			expected: ".- -... -.-.",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Morse(tt.input)
			if result != tt.expected {
				t.Errorf("Morse(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

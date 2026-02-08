package encoding

import "testing"

func TestROT13(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase letters",
			input:    "hello",
			expected: "uryyb",
		},
		{
			name:     "uppercase letters",
			input:    "HELLO",
			expected: "URYYB",
		},
		{
			name:     "mixed case",
			input:    "Hello World",
			expected: "Uryyb Jbeyq",
		},
		{
			name:     "with numbers",
			input:    "abc123",
			expected: "nop123",
		},
		{
			name:     "with special chars",
			input:    "test!@#",
			expected: "grfg!@#",
		},
		{
			name:     "alphabet wrap around",
			input:    "xyz",
			expected: "klm",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ROT13(tt.input)
			if result != tt.expected {
				t.Errorf("ROT13(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

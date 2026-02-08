package encoding

import "testing"

func TestLeet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "all transformable chars lowercase",
			input:    "ieaost",
			expected: "134057",
		},
		{
			name:     "all transformable chars uppercase",
			input:    "IEAOST",
			expected: "134057",
		},
		{
			name:     "mixed case",
			input:    "Hello",
			expected: "H3ll0",
		},
		{
			name:     "test word",
			input:    "test",
			expected: "7357",
		},
		{
			name:     "with non-transformable chars",
			input:    "abc123",
			expected: "4bc123",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Leet(tt.input)
			if result != tt.expected {
				t.Errorf("Leet(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

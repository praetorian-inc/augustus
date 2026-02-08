package encoding

import "testing"

func TestAtbash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase alphabet",
			input:    "abc",
			expected: "zyx",
		},
		{
			name:     "uppercase alphabet",
			input:    "ABC",
			expected: "ZYX",
		},
		{
			name:     "mixed case",
			input:    "Hello",
			expected: "Svool",
		},
		{
			name:     "alphabet endpoints",
			input:    "az AZ",
			expected: "za ZA",
		},
		{
			name:     "with numbers",
			input:    "test123",
			expected: "gvhg123",
		},
		{
			name:     "with special chars",
			input:    "a!b@c",
			expected: "z!y@x",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Atbash(tt.input)
			if result != tt.expected {
				t.Errorf("Atbash(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

package encoding

import "testing"

func TestNATO(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple word",
			input:    "HELLO",
			expected: "Hotel Echo Lima Lima Oscar",
		},
		{
			name:     "lowercase converted",
			input:    "hello",
			expected: "Hotel Echo Lima Lima Oscar",
		},
		{
			name:     "with spaces",
			input:    "HI THERE",
			expected: "Hotel India Tango Hotel Echo Romeo Echo",
		},
		{
			name:     "numbers ignored",
			input:    "A1B2",
			expected: "Alfa Bravo",
		},
		{
			name:     "special chars ignored",
			input:    "A!B@",
			expected: "Alfa Bravo",
		},
		{
			name:     "alphabet",
			input:    "ABCXYZ",
			expected: "Alfa Bravo Charlie Xray Yankee Zulu",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NATO(tt.input)
			if result != tt.expected {
				t.Errorf("NATO(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

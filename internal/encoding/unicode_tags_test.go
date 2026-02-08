package encoding

import "testing"

func TestUnicodeTags(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:  "single letter A",
			input: "A",
			// 'A' = 0x41, tag char = U+E0041
			expected: "\U0001F608\U000E0041",
		},
		{
			name:  "space character",
			input: " ",
			// ' ' = 0x20, tag char = U+E0020
			expected: "\U0001F608\U000E0020",
		},
		{
			name:  "hello",
			input: "hello",
			// h=0x68, e=0x65, l=0x6C, l=0x6C, o=0x6F
			expected: "\U0001F608\U000E0068\U000E0065\U000E006C\U000E006C\U000E006F",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "\U0001F608", // Just the emoji prefix
		},
		{
			name:  "printable ASCII range boundaries",
			input: " ~",
			// 0x20 and 0x7E are both within range
			expected: "\U0001F608\U000E0020\U000E007E",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnicodeTags(tt.input)
			if result != tt.expected {
				t.Errorf("UnicodeTags(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestUnicodeTagsIgnoresNonPrintableASCII(t *testing.T) {
	// Characters outside 0x20-0x7E should be skipped
	result := UnicodeTags("\x01\x7F")
	expected := "\U0001F608" // Only the emoji, no tag chars
	if result != expected {
		t.Errorf("UnicodeTags with non-printable = %q, want %q", result, expected)
	}
}

func TestUnicodeTagsIgnoresUnicode(t *testing.T) {
	// Non-ASCII Unicode characters should be skipped
	result := UnicodeTags("\u00E9") // e-acute
	expected := "\U0001F608"        // Only the emoji
	if result != expected {
		t.Errorf("UnicodeTags with Unicode = %q, want %q", result, expected)
	}
}

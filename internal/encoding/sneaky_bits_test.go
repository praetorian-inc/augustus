package encoding

import (
	"fmt"
	"testing"
)

func TestSneakyBits(t *testing.T) {
	// Helper: encode a single char manually for test verification
	// 'A' = 0x41 = binary 1000001
	// binary encoding: 1=\u2064, 0=\u2062, 0=\u2062, 0=\u2062, 0=\u2062, 0=\u2062, 1=\u2064
	aBits := "\u2064\u2062\u2062\u2062\u2062\u2062\u2064"

	// 'a' = 0x61 = binary 1100001
	aLowerBits := "\u2064\u2064\u2062\u2062\u2062\u2062\u2064"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single uppercase A",
			input:    "A",
			expected: aBits,
		},
		{
			name:     "single lowercase a",
			input:    "a",
			expected: aLowerBits,
		},
		{
			name:     "space becomes zero-width space",
			input:    " ",
			expected: "\u200B",
		},
		{
			name:     "two chars with space",
			input:    "A a",
			expected: aBits + "\u200B" + aLowerBits,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SneakyBits(tt.input)
			if result != tt.expected {
				t.Errorf("SneakyBits(%q):\n  got  %s\n  want %s",
					tt.input, formatZeroWidth(result), formatZeroWidth(tt.expected))
			}
		})
	}
}

// formatZeroWidth converts zero-width characters to readable format for error messages.
func formatZeroWidth(s string) string {
	var result string
	for _, r := range s {
		switch r {
		case '\u2062':
			result += "0"
		case '\u2064':
			result += "1"
		case '\u200B':
			result += "<ZWS>"
		default:
			result += fmt.Sprintf("<%U>", r)
		}
	}
	return result
}

func TestSneakyBitsAllBitsUsed(t *testing.T) {
	// Verify that output only contains the expected zero-width characters
	result := SneakyBits("Hello World")
	for _, r := range result {
		switch r {
		case '\u2062', '\u2064', '\u200B':
			// Expected characters
		default:
			t.Errorf("SneakyBits(\"Hello World\") contains unexpected rune %U", r)
		}
	}
}

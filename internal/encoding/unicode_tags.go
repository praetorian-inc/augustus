package encoding

import "strings"

// UnicodeTags encodes a string using Unicode tag characters.
//
// This function transforms text into invisible Unicode tag characters that encode
// ASCII values. Unicode tag characters (U+E0000 to U+E007F) must be appended to
// an emoji per the Unicode spec. This function prepends the defaultEmoji (😈).
func UnicodeTags(s string) string {
	var output strings.Builder
	output.WriteString(unicodeTagsDefaultEmoji)

	for _, ch := range s {
		// Only encode printable ASCII (0x20-0x7E)
		if ch >= 0x20 && ch <= 0x7E {
			// Convert to Unicode tag character: chr(0xE0000 + ord(ch))
			tagChar := rune(unicodeTagBase + int(ch))
			output.WriteRune(tagChar)
		}
	}

	return output.String()
}

const (
	// unicodeTagsDefaultEmoji is the emoji prepended to the encoded payload.
	unicodeTagsDefaultEmoji = "😈"

	// unicodeTagBase is the base value for Unicode tag characters (U+E0000).
	unicodeTagBase = 0xE0000
)

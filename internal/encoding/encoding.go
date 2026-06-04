// Package encoding provides shared encoding/decoding functions used by
// buffs for LLM security testing.
//
// This package centralizes common encoding logic used by internal/buffs/encoding/.
package encoding

import (
	"unicode"
	"unicode/utf8"
)

// SplitTrailingPunctuation separates a word into its alphanumeric base
// and any trailing non-alphanumeric characters.
// For example: "hello!" → ("hello", "!"), "world..." → ("world", "..."),
// "café!" → ("café", "!").
//
// Unicode combining marks (e.g., U+0301 COMBINING ACUTE ACCENT) are treated
// as part of the base when they follow a letter or digit, so decomposed text
// like "cafe\u0301!" splits correctly as ("cafe\u0301", "!").
func SplitTrailingPunctuation(word string) (string, string) {
	end := len(word)
	markStart := end // tracks where combining marks begin

	for end > 0 {
		ch, size := utf8.DecodeLastRuneInString(word[:end])
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			// Found the base character. Combining marks that immediately
			// follow it (between end and markStart) belong to the base.
			end = markStart
			break
		}
		// Combining marks (Mn = nonspacing, Mc = spacing) attach to the
		// preceding base character. Track them separately so they stay
		// in the base once we find the letter/digit they modify.
		if unicode.Is(unicode.Mn, ch) || unicode.Is(unicode.Mc, ch) {
			end -= size
			continue
		}
		// Non-letter, non-digit, non-mark: this is punctuation.
		end -= size
		markStart = end
	}

	if end == 0 {
		return "", word
	}

	return word[:end], word[end:]
}

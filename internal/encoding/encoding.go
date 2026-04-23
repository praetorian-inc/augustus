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
func SplitTrailingPunctuation(word string) (string, string) {
	end := len(word)
	for end > 0 {
		ch, size := utf8.DecodeLastRuneInString(word[:end])
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			break
		}
		end -= size
	}

	if end == 0 {
		return "", word
	}

	return word[:end], word[end:]
}

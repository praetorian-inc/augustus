// Package encoding provides shared encoding/decoding functions used by
// buffs for LLM security testing.
//
// This package centralizes common encoding logic used by internal/buffs/encoding/.
package encoding

// SplitTrailingPunctuation separates a word into its alphanumeric base
// and any trailing non-alphanumeric characters.
// For example: "hello!" → ("hello", "!"), "world..." → ("world", "...").
func SplitTrailingPunctuation(word string) (string, string) {
	lastAlnum := -1
	for i := len(word) - 1; i >= 0; i-- {
		ch := rune(word[i])
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			lastAlnum = i
			break
		}
	}

	if lastAlnum == -1 {
		return "", word
	}

	return word[:lastAlnum+1], word[lastAlnum+1:]
}

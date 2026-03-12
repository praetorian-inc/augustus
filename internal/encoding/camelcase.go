package encoding

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// CamelCase encodes the input string using camelCase word joining.
// The first word is lowercased entirely, and each subsequent word has its
// first letter capitalized with the rest unchanged. All words are joined
// with no separator.
func CamelCase(s string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var b strings.Builder
	// First word: lowercase entirely
	b.WriteString(strings.ToLower(words[0]))

	// Subsequent words: capitalize first rune, rest unchanged
	for _, w := range words[1:] {
		r, size := utf8.DecodeRuneInString(w)
		b.WriteRune(unicode.ToUpper(r))
		b.WriteString(w[size:])
	}

	return b.String()
}

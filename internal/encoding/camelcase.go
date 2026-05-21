package encoding

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// CamelCase encodes the input string using camelCase word joining.
// The first word is lowercased entirely, and each subsequent word has its
// first letter capitalized and the rest lowercased. All words are joined
// with no separator.
func CamelCase(s string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(strings.ToLower(words[0]))

	for _, w := range words[1:] {
		r, size := utf8.DecodeRuneInString(w)
		b.WriteRune(unicode.ToUpper(r))
		b.WriteString(strings.ToLower(w[size:]))
	}

	return b.String()
}

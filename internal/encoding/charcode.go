package encoding

import (
	"strconv"
	"strings"
)

// CharCode converts each character in the string to its Unicode code point,
// returning the decimal codes separated by spaces.
//
// For example, "Hi" becomes "72 105" (Unicode code points for 'H' and 'i').
// Iterates runes for proper Unicode handling (equivalent to Python's ord()).
func CharCode(s string) string {
	if s == "" {
		return ""
	}

	codes := make([]string, 0, len(s))
	for _, r := range s {
		codes = append(codes, strconv.Itoa(int(r)))
	}
	return strings.Join(codes, " ")
}

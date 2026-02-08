package encoding

import (
	"fmt"
	"strings"
)

// SneakyBits encodes a string using Sneaky Bits encoding.
//
// This function transforms text by encoding ASCII characters into binary and encoding
// that binary using zero-width Unicode characters (invisible times for 0, invisible
// plus for 1). Space characters are replaced with zero-width space.
func SneakyBits(s string) string {
	var output strings.Builder

	for _, ch := range s {
		// Handle space characters specially
		if ch == 0x20 {
			output.WriteRune(zeroWidthSpace)
			continue
		}

		// Convert character to binary and encode each bit
		binary := fmt.Sprintf("%b", ch)
		for _, bit := range binary {
			if bit == '0' {
				output.WriteRune(invisibleTimes)
			} else {
				output.WriteRune(invisiblePlus)
			}
		}
	}

	return output.String()
}

const (
	// invisibleTimes (U+2062) represents binary 0.
	invisibleTimes = '\u2062'

	// invisiblePlus (U+2064) represents binary 1.
	invisiblePlus = '\u2064'

	// zeroWidthSpace (U+200B) replaces space characters.
	zeroWidthSpace = '\u200B'
)

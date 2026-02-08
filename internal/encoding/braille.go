package encoding

import "strings"

// Braille encodes a string using Braille Unicode characters.
//
// This function transforms text into Braille Unicode characters. Uppercase letters
// are prefixed with a capital indicator (\u2820), numbers are prefixed with a number
// indicator (\u283C), and escape characters (\n, \r, \t) are preserved unchanged.
func Braille(s string) string {
	return brailleEncode(s)
}

// brailleMap maps ASCII characters to their Unicode braille equivalents.
var brailleMap = map[rune]rune{
	// Lowercase letters
	'a': '\u2801', 'b': '\u2803', 'c': '\u2809', 'd': '\u2819', 'e': '\u2811',
	'f': '\u280B', 'g': '\u281B', 'h': '\u2813', 'i': '\u280A', 'j': '\u281A',
	'k': '\u2805', 'l': '\u2807', 'm': '\u280D', 'n': '\u281D', 'o': '\u2815',
	'p': '\u280F', 'q': '\u281F', 'r': '\u2817', 's': '\u280E', 't': '\u281E',
	'u': '\u2825', 'v': '\u2827', 'w': '\u283A', 'x': '\u282D', 'y': '\u283D',
	'z': '\u2835',

	// Numbers (same as letters a-j when preceded by number indicator)
	'1': '\u2801', '2': '\u2803', '3': '\u2809', '4': '\u2819', '5': '\u2811',
	'6': '\u280B', '7': '\u281B', '8': '\u2813', '9': '\u280A', '0': '\u281A',

	// Punctuation
	'.': '\u2832', '\'': '\u2804', ',': '\u2802', '-': '\u2824', '/': '\u280C',
	'!': '\u2816', '?': '\u2826', '$': '\u2832', ':': '\u2812', ';': '\u2830',
	'(': '\u2836', ')': '\u2836',

	// Space
	' ': ' ',
}

// Special indicators
const (
	brailleCapital = '\u2820' // Capital letter indicator
	brailleNumber  = '\u283C' // Number indicator
)

// numberPunctuations are punctuation marks that can appear in numbers without
// ending number mode.
var numberPunctuations = map[rune]bool{
	'.': true, ',': true, '-': true, '/': true, '$': true,
}

// escapeCharacters are characters that should be passed through unchanged.
var escapeCharacters = map[rune]bool{
	'\n': true, '\r': true, '\t': true,
}

// brailleEncode encodes a payload to Braille Unicode characters.
func brailleEncode(text string) string {
	var output strings.Builder
	inNumberMode := false

	for _, ch := range text {
		// Pass through escape characters unchanged
		if escapeCharacters[ch] {
			output.WriteRune(ch)
			inNumberMode = false
			continue
		}

		// Handle uppercase letters
		if ch >= 'A' && ch <= 'Z' {
			lower := ch + 32 // Convert to lowercase
			if braille, ok := brailleMap[lower]; ok {
				output.WriteRune(brailleCapital)
				output.WriteRune(braille)
			}
			inNumberMode = false
			continue
		}

		// Handle digits
		if ch >= '0' && ch <= '9' {
			if !inNumberMode {
				output.WriteRune(brailleNumber)
				inNumberMode = true
			}
			if braille, ok := brailleMap[ch]; ok {
				output.WriteRune(braille)
			}
			continue
		}

		// Handle other characters
		if braille, ok := brailleMap[ch]; ok {
			output.WriteRune(braille)

			// Exit number mode unless this is a number punctuation
			if inNumberMode && !numberPunctuations[ch] {
				inNumberMode = false
			}
		}
	}

	return output.String()
}

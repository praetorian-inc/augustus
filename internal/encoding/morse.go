package encoding

import "strings"

// morseCode maps characters to their morse code representation.
var morseCode = map[rune]string{
	'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".",
	'F': "..-.", 'G': "--.", 'H': "....", 'I': "..", 'J': ".---",
	'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.", 'O': "---",
	'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-",
	'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--",
	'Z': "--..", '0': "-----", '1': ".----", '2': "..---", '3': "...--",
	'4': "....-", '5': ".....", '6': "-....", '7': "--...", '8': "---..",
	'9': "----.",
	// Whitespace characters map to "/"
	' ': "/", '\n': "/", '\r': "/", '\t': "/",
}

// Morse encodes the input string into Morse code.
// The input is converted to uppercase and each character is mapped to its
// Morse code representation. Characters are joined with spaces.
// Whitespace characters (space, newline, tab) are mapped to "/".
// Unknown characters are ignored.
func Morse(s string) string {
	text := strings.ToUpper(s)
	var output []string
	for _, char := range text {
		if code, ok := morseCode[char]; ok {
			output = append(output, code)
		}
	}
	return strings.Join(output, " ")
}

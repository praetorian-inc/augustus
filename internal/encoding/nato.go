package encoding

import "strings"

// natoAlphabet maps characters to their NATO phonetic alphabet representation.
var natoAlphabet = map[rune]string{
	'A': "Alfa", 'B': "Bravo", 'C': "Charlie", 'D': "Delta", 'E': "Echo",
	'F': "Foxtrot", 'G': "Golf", 'H': "Hotel", 'I': "India", 'J': "Juliett",
	'K': "Kilo", 'L': "Lima", 'M': "Mike", 'N': "November", 'O': "Oscar",
	'P': "Papa", 'Q': "Quebec", 'R': "Romeo", 'S': "Sierra", 'T': "Tango",
	'U': "Uniform", 'V': "Victor", 'W': "Whiskey", 'X': "Xray", 'Y': "Yankee",
	'Z': "Zulu",
}

// NATO encodes the input string using NATO phonetic alphabet.
// The input is converted to uppercase and each letter is mapped to its
// NATO phonetic word. Words are joined with spaces.
// Non-letter characters are ignored.
func NATO(s string) string {
	text := strings.ToUpper(s)
	var output []string
	for _, char := range text {
		if word, ok := natoAlphabet[char]; ok {
			output = append(output, word)
		}
	}
	return strings.Join(output, " ")
}

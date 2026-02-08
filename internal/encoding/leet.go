package encoding

// leetMap maps characters to their leetspeak equivalents.
var leetMap = map[rune]rune{
	'i': '1', 'I': '1',
	'e': '3', 'E': '3',
	'a': '4', 'A': '4',
	'o': '0', 'O': '0',
	's': '5', 'S': '5',
	't': '7', 'T': '7',
}

// Leet encodes the input string using Leetspeak (1337) mapping.
// Characters i/e/a/o/s/t are replaced with 1/3/4/0/5/7 respectively.
// Other characters are left unchanged.
func Leet(s string) string {
	result := make([]rune, 0, len(s))
	for _, b := range s {
		if replacement, ok := leetMap[b]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, b)
		}
	}
	return string(result)
}

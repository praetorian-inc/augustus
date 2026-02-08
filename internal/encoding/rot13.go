package encoding

// ROT13 applies ROT13 encoding to the input string.
// ROT13 is a simple letter substitution cipher that replaces each letter
// with the letter 13 positions after it in the alphabet.
// Non-letter characters are left unchanged.
func ROT13(s string) string {
	result := make([]byte, len(s))
	for i, b := range []byte(s) {
		switch {
		case b >= 'a' && b <= 'z':
			result[i] = 'a' + (b-'a'+13)%26
		case b >= 'A' && b <= 'Z':
			result[i] = 'A' + (b-'A'+13)%26
		default:
			result[i] = b
		}
	}
	return string(result)
}

package encoding

// Atbash encodes the input string using Atbash cipher.
// Atbash is a monoalphabetic substitution cipher where the first letter
// of the alphabet is replaced with the last (a↔z, b↔y, etc.).
// Non-letter characters are left unchanged.
func Atbash(s string) string {
	result := make([]byte, len(s))
	for i, b := range []byte(s) {
		switch {
		case b >= 'a' && b <= 'z':
			result[i] = 'z' - (b - 'a')
		case b >= 'A' && b <= 'Z':
			result[i] = 'Z' - (b - 'A')
		default:
			result[i] = b
		}
	}
	return string(result)
}

package encoding

import "strings"

// PigLatin encodes the input string using Pig Latin rules.
//
// Rules:
//   - Consonant-initial words: move all consonants before the first vowel
//     to the end, then append "ay" (e.g., "hello" → "ellohay", "string" → "ingstray").
//   - Vowel-initial words: append "way" (e.g., "apple" → "appleway").
//   - Words with no vowels: append "ay" (e.g., "shy" → "shyay").
//   - Trailing punctuation is preserved after the suffix.
//   - Words not starting with a letter are returned unchanged.
//
// Note: 'y' is not treated as a vowel. Capitalization is not normalized;
// letters move with their original casing.
func PigLatin(s string) string {
	words := strings.Split(s, " ")
	result := make([]string, len(words))

	for i, word := range words {
		result[i] = pigLatinWord(word)
	}

	return strings.Join(result, " ")
}

func pigLatinWord(word string) string {
	if word == "" {
		return word
	}

	// Split into base (alphanumeric) and trailing punctuation.
	base, punctuation := SplitTrailingPunctuation(word)
	if base == "" {
		return word
	}

	// Words not starting with a letter are returned unchanged.
	first := rune(base[0])
	if !isLetter(first) {
		return word
	}

	// Vowel-initial: append "way".
	if isVowel(first) {
		return base + "way" + punctuation
	}

	// Find the first vowel position.
	vowelIdx := -1
	for j, ch := range base {
		if j > 0 && isVowel(ch) {
			vowelIdx = j
			break
		}
	}

	// No vowels: append "ay".
	if vowelIdx == -1 {
		return base + "ay" + punctuation
	}

	// Consonant cluster: move prefix to end + "ay".
	return base[vowelIdx:] + base[:vowelIdx] + "ay" + punctuation
}

func isVowel(ch rune) bool {
	switch ch {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}


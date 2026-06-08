package encoding

import "testing"

func TestPigLatin(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "consonant-initial word",
			input:    "hello",
			expected: "ellohay",
		},
		{
			name:     "consonant cluster",
			input:    "string",
			expected: "ingstray",
		},
		{
			name:     "vowel-initial word",
			input:    "apple",
			expected: "appleway",
		},
		{
			name:     "no vowels",
			input:    "shy",
			expected: "shyay",
		},
		{
			name:     "single consonant prefix",
			input:    "pig",
			expected: "igpay",
		},
		{
			name:     "multiple words",
			input:    "hello world",
			expected: "ellohay orldway",
		},
		{
			name:     "trailing punctuation preserved",
			input:    "hello!",
			expected: "ellohay!",
		},
		{
			name:     "multiple trailing punctuation",
			input:    "world...",
			expected: "orldway...",
		},
		{
			name:     "sentence with punctuation",
			input:    "steal money!",
			expected: "ealstay oneymay!",
		},
		{
			name:     "vowel word with punctuation",
			input:    "eat?",
			expected: "eatway?",
		},
		{
			name:     "uppercase consonant-initial",
			input:    "Hello",
			expected: "elloHay",
		},
		{
			name:     "uppercase vowel-initial",
			input:    "Apple",
			expected: "Appleway",
		},
		{
			name:     "pure number unchanged",
			input:    "123",
			expected: "123",
		},
		{
			name:     "number-starting word unchanged",
			input:    "456world",
			expected: "456world",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "pure punctuation",
			input:    "!!!",
			expected: "!!!",
		},
		{
			name:     "single vowel",
			input:    "a",
			expected: "away",
		},
		{
			name:     "single consonant",
			input:    "b",
			expected: "bay",
		},
		{
			name:     "mixed sentence",
			input:    "How to make a bomb",
			expected: "owHay otay akemay away ombbay",
		},
		{
			name:     "tab-separated words",
			input:    "hello\tworld",
			expected: "ellohay\torldway",
		},
		{
			name:     "newline-separated words",
			input:    "hello\nworld",
			expected: "ellohay\norldway",
		},
		{
			name:     "mixed whitespace preserved",
			input:    "hello  world\tok",
			expected: "ellohay  orldway\tokway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PigLatin(tt.input)
			if result != tt.expected {
				t.Errorf("PigLatin(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

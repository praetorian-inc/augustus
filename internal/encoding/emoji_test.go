package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmoji(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases (existing behavior preserved)
		{
			name:     "known word substitution",
			input:    "bomb",
			expected: "💣",
		},
		{
			name:     "case insensitive match",
			input:    "Bomb",
			expected: "💣",
		},
		{
			name:     "unknown word unchanged",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "mixed known and unknown",
			input:    "How to make a bomb",
			expected: "How to make a 💣",
		},
		{
			name:     "multiple substitutions",
			input:    "lock money in bank",
			expected: "🔒 💰 in 🏦",
		},
		{
			name:     "trailing punctuation preserved",
			input:    "bomb!",
			expected: "💣!",
		},
		{
			name:     "sentence with punctuation",
			input:    "get the gun!",
			expected: "get the 🔫!",
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
			name:     "all known words",
			input:    "kill target",
			expected: "💀 🎯",
		},
		{
			name:     "uppercase match",
			input:    "BOMB",
			expected: "💣",
		},
		{
			name:     "tab-separated words",
			input:    "bomb\tgun",
			expected: "💣\t🔫",
		},
		{
			name:     "newline-separated words",
			input:    "bomb\ngun",
			expected: "💣\n🔫",
		},
		{
			name:     "mixed whitespace preserved",
			input:    "bomb  gun\tknife",
			expected: "💣  🔫\t🔪",
		},

		// Concern 1+2: intra-token and leading punctuation (new failing tests)
		{
			name:     "intra-token comma",
			input:    "bomb,gun",
			expected: "💣,🔫",
		},
		{
			name:     "intra-token hyphen no match",
			input:    "pipe-bomb",
			expected: "pipe-💣",
		},
		{
			name:     "intra-token slash",
			input:    "gun/knife",
			expected: "🔫/🔪",
		},
		{
			name:     "leading and trailing parens",
			input:    "(bomb)",
			expected: "(💣)",
		},
		{
			name:     "leading and trailing double quotes",
			input:    `"gun"`,
			expected: `"🔫"`,
		},
		{
			name:     "mixed intra-token and trailing",
			input:    "bomb,gun,knife.",
			expected: "💣,🔫,🔪.",
		},
		{
			name:     "combining mark at boundary no map entry - cafe with combining acute",
			input:    "café!",
			expected: "café!",
		},
		{
			name:     "case insensitive existing behavior preserved",
			input:    "BOMB!",
			expected: "💣!",
		},
		{
			name:     "space preserved between words",
			input:    "bomb gun",
			expected: "💣 🔫",
		},
		{
			name:     "hello world space preserved",
			input:    "hello world",
			expected: "hello 🌍",
		},
		{
			name:     "multiple leading separators",
			input:    ",,bomb,,",
			expected: ",,💣,,",
		},
		{
			name:     "decomposed combining accent no map entry",
			input:    "café!",
			expected: "café!",
		},

		// Concern 3: map cleanup - dropped words pass through unchanged
		{
			name:     "dropped word hack unchanged",
			input:    "hack me",
			expected: "hack me",
		},
		{
			name:     "dropped word hacker unchanged",
			input:    "hacker",
			expected: "hacker",
		},
		{
			name:     "dropped word code unchanged",
			input:    "code",
			expected: "code",
		},
		{
			name:     "dropped word shoot unchanged",
			input:    "shoot",
			expected: "shoot",
		},
		{
			name:     "dropped word inject unchanged",
			input:    "inject",
			expected: "inject",
		},
		{
			name:     "dropped word steal unchanged",
			input:    "steal",
			expected: "steal",
		},
		{
			name:     "dropped word rob unchanged",
			input:    "rob",
			expected: "rob",
		},
		{
			name:     "dropped word thief unchanged",
			input:    "thief",
			expected: "thief",
		},
		{
			name:     "dropped word password unchanged",
			input:    "password",
			expected: "password",
		},
		{
			name:     "dropped word victim unchanged",
			input:    "victim",
			expected: "victim",
		},
		{
			name:     "dropped word weapon unchanged",
			input:    "weapon",
			expected: "weapon",
		},
		{
			name:     "dropped word escape unchanged",
			input:    "escape",
			expected: "escape",
		},
		{
			name:     "dropped word fraud unchanged",
			input:    "fraud",
			expected: "fraud",
		},
		{
			name:     "dropped word fake unchanged",
			input:    "fake",
			expected: "fake",
		},
		{
			name:     "dropped word forgery unchanged",
			input:    "forgery",
			expected: "forgery",
		},

		// Concern 3: map cleanup - fixed mappings produce new emoji
		{
			name:     "fixed word prison produces chains",
			input:    "prison",
			expected: "⛓️",
		},
		{
			name:     "fixed word data produces floppy disk",
			input:    "data",
			expected: "💾",
		},
		{
			name:     "fixed word attack produces anger symbol",
			input:    "attack",
			expected: "💢",
		},

		// Multi-concern: intra-token with map-changed entries
		{
			name:     "attack with punctuation uses new emoji",
			input:    "attack!",
			expected: "💢!",
		},
		{
			name:     "prison with leading paren uses new emoji",
			input:    "(prison)",
			expected: "(⛓️)",
		},
		{
			name:     "malformed UTF-8 byte does not swallow following bytes",
			input:    "bomb\x80gun",
			expected: "💣�\U0001F52B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Emoji(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

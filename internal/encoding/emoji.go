package encoding

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// emojiMap maps common words and security-relevant terms to emoji equivalents.
// This mapping targets terms frequently appearing in adversarial prompts
// to test whether emoji substitution evades LLM safety filters.
var emojiMap = map[string]string{
	// Weapons and violence
	"bomb":      "💣",
	"gun":       "🔫",
	"knife":     "🔪",
	"sword":     "⚔️",
	"kill":      "💀",
	"dead":      "💀",
	"death":     "💀",
	"attack":    "💢",
	"fight":     "👊",
	"explode":   "💥",
	"explosion": "💥",
	"fire":      "🔥",
	"poison":    "☠️",
	"danger":    "⚠️",
	"warning":   "⚠️",

	// Crime and theft
	"money":  "💰",
	"cash":   "💵",
	"bank":   "🏦",
	"lock":   "🔒",
	"unlock": "🔓",
	"key":    "🔑",
	"secret": "🤫",
	"hide":   "🫣",
	"prison": "⛓️",
	"police": "👮",

	// Drugs and substances
	"drug":   "💊",
	"drugs":  "💊",
	"pill":   "💊",
	"smoke":  "🚬",
	"needle": "💉",

	// Digital and cyber
	"computer": "💻",
	"virus":    "🦠",
	"malware":  "🦠",
	"email":    "📧",
	"phone":    "📱",
	"network":  "🌐",
	"internet": "🌐",
	"data":     "💾",
	"encrypt":  "🔐",
	"decrypt":  "🔓",

	// People and actions
	"person": "🧑",
	"people": "👥",
	"man":    "👨",
	"woman":  "👩",
	"child":  "🧒",
	"target": "🎯",
	"help":   "🆘",
	"stop":   "🛑",
	"run":    "🏃",
	"search": "🔍",
	"find":   "🔍",
	"watch":  "👀",
	"see":    "👀",
	"listen": "👂",
	"talk":   "🗣️",
	"say":    "🗣️",

	// Places and objects
	"house": "🏠",
	"home":  "🏠",
	"car":   "🚗",
	"door":  "🚪",
	"window": "🪟",
	"world":  "🌍",
	"earth":  "🌍",

	// Abstract
	"love":  "❤️",
	"hate":  "😡",
	"angry": "😡",
	"happy": "😊",
	"sad":   "😢",
	"fear":  "😨",
	"think": "🤔",
	"idea":  "💡",
	"time":  "⏰",
	"fast":  "⚡",
	"slow":  "🐌",
	"big":   "🐘",
	"small": "🐜",
	"yes":   "✅",
	"no":    "❌",
	"good":  "👍",
	"bad":   "👎",
	"right": "✅",
	"wrong": "❌",
}

// isWordRune reports whether r is a word character: letter, digit, or combining
// mark (nonspacing Mn or spacing Mc). Combining marks attach to the preceding
// letter, so they stay in the word segment.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r)
}

// Emoji encodes the input string by replacing known words with emoji equivalents.
// Words are matched case-insensitively. Unrecognized words pass through unchanged.
//
// A word is a contiguous run of letters, digits, and combining marks. Everything
// else (whitespace, punctuation, symbols) is a separator and is emitted verbatim.
// This handles intra-token punctuation (bomb,gun → 💣,🔫) and leading/trailing
// punctuation ((bomb) → (💣)) in a single pass.
func Emoji(s string) string {
	var result strings.Builder
	result.Grow(len(s))

	wordStart := -1 // byte index where current word segment began

	flush := func(end int) {
		if wordStart == -1 {
			return
		}
		word := s[wordStart:end]
		lower := strings.ToLower(word)
		if emoji, ok := emojiMap[lower]; ok {
			result.WriteString(emoji)
		} else {
			result.WriteString(word)
		}
		wordStart = -1
	}

	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isWordRune(r) {
			if wordStart == -1 {
				wordStart = i
			}
		} else {
			flush(i)
			result.WriteRune(r)
		}
		i += size
	}
	flush(len(s))

	return result.String()
}

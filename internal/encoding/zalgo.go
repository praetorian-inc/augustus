package encoding

import (
	"math/rand"
	"strings"
)

// Zalgo encodes a string using Zalgo text transformation.
//
// This function adds Unicode combining diacritical marks above and below each
// character, creating "corrupted" or "glitchy" text appearance. The intensity
// parameter controls how many diacritics to add per character (default: 5).
func Zalgo(s string) string {
	return zalgoWithIntensity(s, 5)
}

const (
	// zalgoIntensity controls how many diacritics to add per character.
	zalgoIntensity = 5
)

// Unicode combining diacritical marks
var (
	combiningAbove = []rune{
		'\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
		'\u0308', '\u0309', '\u030A', '\u030B', '\u030C', '\u030D', '\u030E', '\u030F',
		'\u0310', '\u0311', '\u0312', '\u0313', '\u0314',
	}

	combiningBelow = []rune{
		'\u0316', '\u0317', '\u0318', '\u0319', '\u031A', '\u031B', '\u031C', '\u031D',
		'\u031E', '\u031F', '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325',
		'\u0326', '\u0327', '\u0328', '\u0329', '\u032A', '\u032B', '\u032C', '\u032D',
		'\u032E', '\u032F', '\u0330', '\u0331', '\u0332', '\u0333',
	}

	combiningMiddle = []rune{
		'\u0334', '\u0335', '\u0336', '\u0337', '\u0338', '\u0339', '\u033A', '\u033B',
		'\u033C', '\u033D', '\u033E', '\u033F',
	}
)

func zalgoWithIntensity(text string, intensity int) string {
	var result strings.Builder

	for _, char := range text {
		// Add the original character
		result.WriteRune(char)

		// Skip whitespace and control characters
		if char <= ' ' || char == '\n' || char == '\r' || char == '\t' {
			continue
		}

		// Add marks above
		numAbove := rand.Intn(intensity + 1)
		for i := 0; i < numAbove; i++ {
			mark := combiningAbove[rand.Intn(len(combiningAbove))]
			result.WriteRune(mark)
		}

		// Add marks below
		numBelow := rand.Intn(intensity + 1)
		for i := 0; i < numBelow; i++ {
			mark := combiningBelow[rand.Intn(len(combiningBelow))]
			result.WriteRune(mark)
		}

		// Add marks through middle (less frequently)
		if rand.Float32() < 0.3 { // 30% chance
			numMiddle := rand.Intn(intensity/2 + 1)
			for i := 0; i < numMiddle; i++ {
				mark := combiningMiddle[rand.Intn(len(combiningMiddle))]
				result.WriteRune(mark)
			}
		}
	}

	return result.String()
}

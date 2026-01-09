package encoding

import (
	"math/rand"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectZalgo", NewInjectZalgo)
}

// InjectZalgo probes for susceptibility to Zalgo text encoded injections.
//
// Zalgo text uses Unicode combining diacritical marks to create "corrupted" or
// "glitchy" text appearance. This probe encodes payloads using Zalgo decoration
// and tries various ways of getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectZalgo
// Reference: https://en.wikipedia.org/wiki/Zalgo_text
type InjectZalgo struct {
	*EncodingProbe
}

// NewInjectZalgo creates a new InjectZalgo probe.
func NewInjectZalgo(_ registry.Config) (probes.Prober, error) {
	// Zalgo encoding function with intensity=5 (matches garak default)
	// Python uses zalgolib.enzalgofy(text, intensity=5)
	// Note: default intensity of 50 would explode prompt length
	encoders := []Encoder{
		func(data []byte) string {
			return zalgoEncode(data, 5)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectZalgo",
		"Zalgo",
		FormatDescription("Zalgo"),
		encoders,
	)

	return &InjectZalgo{
		EncodingProbe: base,
	}, nil
}

// zalgoEncode applies Zalgo text transformation to the input.
// It adds Unicode combining diacritical marks above and below each character.
//
// intensity: controls how many diacritics to add per character (1-10 recommended)
//
// Implementation based on Zalgo text algorithm:
// - Combining diacritics range: U+0300 to U+036F
// - Above: U+0300 to U+0314 (marks above)
// - Below: U+0316 to U+0333 (marks below)
// - Middle: U+0334 to U+036F (marks through)
func zalgoEncode(input []byte, intensity int) string {
	// Unicode combining diacritical marks
	// https://en.wikipedia.org/wiki/Combining_character
	combiningAbove := []rune{
		// Combining diacritics above
		'\u0300', '\u0301', '\u0302', '\u0303', '\u0304', '\u0305', '\u0306', '\u0307',
		'\u0308', '\u0309', '\u030A', '\u030B', '\u030C', '\u030D', '\u030E', '\u030F',
		'\u0310', '\u0311', '\u0312', '\u0313', '\u0314',
	}

	combiningBelow := []rune{
		// Combining diacritics below
		'\u0316', '\u0317', '\u0318', '\u0319', '\u031A', '\u031B', '\u031C', '\u031D',
		'\u031E', '\u031F', '\u0320', '\u0321', '\u0322', '\u0323', '\u0324', '\u0325',
		'\u0326', '\u0327', '\u0328', '\u0329', '\u032A', '\u032B', '\u032C', '\u032D',
		'\u032E', '\u032F', '\u0330', '\u0331', '\u0332', '\u0333',
	}

	combiningMiddle := []rune{
		// Combining diacritics through middle
		'\u0334', '\u0335', '\u0336', '\u0337', '\u0338', '\u0339', '\u033A', '\u033B',
		'\u033C', '\u033D', '\u033E', '\u033F',
	}

	var result strings.Builder
	text := string(input)

	for _, char := range text {
		// Add the original character
		result.WriteRune(char)

		// Skip whitespace and control characters
		if char <= ' ' || char == '\n' || char == '\r' || char == '\t' {
			continue
		}

		// Add random combining marks based on intensity
		// For each character, add marks above, below, and through

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

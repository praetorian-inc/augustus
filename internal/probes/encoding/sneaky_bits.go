package encoding

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectSneakyBits", NewInjectSneakyBits)
}

// InjectSneakyBits probes for susceptibility to Sneaky Bits encoding.
//
// Encodes payloads by encoding ASCII characters into binary and encoding that
// binary using zero-width Unicode characters (invisible times for 0, invisible
// plus for 1), and tries a variety of ways of getting the target model to
// repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectSneakyBits (lines 688-707)
// Reference: https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/
type InjectSneakyBits struct {
	*EncodingProbe
}

// NewInjectSneakyBits creates a new InjectSneakyBits probe.
func NewInjectSneakyBits(_ registry.Config) (probes.Prober, error) {
	// Python uses sneaky_bits_smuggling (encoding.py line 699)
	encoders := []Encoder{
		sneakyBitsEncode,
	}

	base := NewEncodingProbe(
		"encoding.InjectSneakyBits",
		"ASCII in hidden unicode binary encoding",
		FormatDescription("ASCII in hidden unicode binary encoding"),
		encoders,
	)

	return &InjectSneakyBits{
		EncodingProbe: base,
	}, nil
}

const (
	// invisibleTimes (U+2062) represents binary 0.
	// Matches Python char_map["0"] in smuggle_ascii.py line 64.
	invisibleTimes = '\u2062'

	// invisiblePlus (U+2064) represents binary 1.
	// Matches Python char_map["1"] in smuggle_ascii.py line 64.
	invisiblePlus = '\u2064'

	// zeroWidthSpace (U+200B) replaces space characters.
	// Matches Python smuggle_ascii.py line 68 for ord(ch) == 0x20.
	zeroWidthSpace = '\u200B'
)

// sneakyBitsEncode encodes a payload using Sneaky Bits technique.
// Matches Python sneaky_bits_smuggling() in smuggle_ascii.py (lines 50-72).
//
// Each ASCII character is converted to its binary representation.
// Binary digits are encoded as invisible Unicode characters:
//   - '0' → U+2062 (INVISIBLE TIMES)
//   - '1' → U+2064 (INVISIBLE PLUS)
// Spaces are replaced with U+200B (ZERO-WIDTH SPACE).
//
// Reference: https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/
func sneakyBitsEncode(payload []byte) string {
	text := string(payload)
	var output strings.Builder

	for _, ch := range text {
		// Handle space characters specially (smuggle_ascii.py lines 67-68)
		if ch == 0x20 {
			output.WriteRune(zeroWidthSpace)
			continue
		}

		// Convert character to binary and encode each bit
		// (smuggle_ascii.py lines 70-71)
		binary := fmt.Sprintf("%b", ch)
		for _, bit := range binary {
			if bit == '0' {
				output.WriteRune(invisibleTimes)
			} else {
				output.WriteRune(invisiblePlus)
			}
		}
	}

	return output.String()
}

package encoding

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectUnicodeTagChars", NewInjectUnicodeTagChars)
}

// InjectUnicodeTagChars probes for susceptibility to Unicode tag ASCII smuggling.
//
// Encodes payloads by appending them to an emoji as invisible ASCII tags, and tries
// a variety of ways of getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectUnicodeTagChars (lines 642-667)
// Reference: https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/
type InjectUnicodeTagChars struct {
	*EncodingProbe
}

// NewInjectUnicodeTagChars creates a new InjectUnicodeTagChars probe.
func NewInjectUnicodeTagChars(_ registry.Config) (probes.Prober, error) {
	// Python uses tag_char_smuggling with default emoji (encoding.py lines 656-666)
	encoders := []Encoder{
		tagCharEncode,
	}

	base := NewEncodingProbe(
		"encoding.InjectUnicodeTagChars",
		"ASCII in Unicode Tags",
		FormatDescription("ASCII in Unicode Tags"),
		encoders,
	)

	return &InjectUnicodeTagChars{
		EncodingProbe: base,
	}, nil
}

const (
	// defaultEmoji is the emoji prepended to the encoded payload.
	// Matches Python DEFAULT_PARAMS in encoding.py line 654.
	defaultEmoji = "😈"

	// unicodeTagBase is the base value for Unicode tag characters (U+E0000).
	// Each ASCII character is encoded as: chr(0xE0000 + ord(char))
	// Reference: smuggle_ascii.py line 29
	unicodeTagBase = 0xE0000
)

// tagCharEncode encodes a payload using Unicode tag characters.
// Matches Python tag_char_smuggling() in smuggle_ascii.py (lines 15-30).
//
// Unicode tag characters (U+E0000 to U+E007F) are invisible but encode ASCII values.
// They must be appended to an emoji per the Unicode spec.
// Reference: https://unicode.org/reports/tr51/
func tagCharEncode(payload []byte) string {
	text := string(payload)
	var output strings.Builder

	// Start with the emoji
	output.WriteString(defaultEmoji)

	// Encode each character as a Unicode tag character
	// Only printable ASCII (0x20-0x7E) should be encoded
	for _, ch := range text {
		if ch >= 0x20 && ch <= 0x7E {
			// Convert to Unicode tag character: chr(0xE0000 + ord(ch))
			tagChar := rune(unicodeTagBase + int(ch))
			output.WriteRune(tagChar)
		}
	}

	return output.String()
}

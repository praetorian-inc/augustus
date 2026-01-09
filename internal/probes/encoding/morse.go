package encoding

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectMorse", NewInjectMorse)
}

// InjectMorse probes for susceptibility to Morse code encoded injections.
//
// Encodes payloads using morse code, and tries a variety of ways of getting the target
// model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectMorse
// Credit: Wally#3422
type InjectMorse struct {
	*EncodingProbe
}

// morseCode maps characters to their morse code representation.
// Matches Python implementation in encoding.py lines 141-183.
var morseCode = map[rune]string{
	'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".",
	'F': "..-.", 'G': "--.", 'H': "....", 'I': "..", 'J': ".---",
	'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.", 'O': "---",
	'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-",
	'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--",
	'Z': "--..", '0': "-----", '1': ".----", '2': "..---", '3': "...--",
	'4': "....-", '5': ".....", '6': "-....", '7': "--...", '8': "---..",
	'9': "----.",
	// Python maps space, newline, carriage return, and tab to "/"
	' ': "/", '\n': "/", '\r': "/", '\t': "/",
}

// NewInjectMorse creates a new InjectMorse probe.
func NewInjectMorse(_ registry.Config) (probes.Prober, error) {
	// Morse encoding function
	// Python implementation (lines 141-189):
	// - Convert to uppercase
	// - Map each character to morse code
	// - Join with spaces between letters
	encoders := []Encoder{
		func(data []byte) string {
			text := strings.ToUpper(string(data))
			var output []string
			for _, char := range text {
				if code, ok := morseCode[char]; ok {
					output = append(output, code)
				}
			}
			return strings.Join(output, " ")
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectMorse",
		"Morse",
		FormatDescription("Morse"),
		encoders,
	)

	return &InjectMorse{
		EncodingProbe: base,
	}, nil
}

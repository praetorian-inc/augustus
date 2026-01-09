package encoding

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectNato", NewInjectNato)
}

// InjectNato probes for susceptibility to NATO phonetic alphabet encoded injections.
//
// Encodes payloads using the classic NATO phonetic alphabet, and tries a variety
// of ways of getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectNato
type InjectNato struct {
	*EncodingProbe
}

// natoAlphabet maps characters to their NATO phonetic alphabet representation.
// Matches Python implementation in encoding.py lines 523-550.
// Note: Python uses "Xray" (line 547) instead of "X-ray"
var natoAlphabet = map[rune]string{
	'A': "Alfa", 'B': "Bravo", 'C': "Charlie", 'D': "Delta", 'E': "Echo",
	'F': "Foxtrot", 'G': "Golf", 'H': "Hotel", 'I': "India", 'J': "Juliett",
	'K': "Kilo", 'L': "Lima", 'M': "Mike", 'N': "November", 'O': "Oscar",
	'P': "Papa", 'Q': "Quebec", 'R': "Romeo", 'S': "Sierra", 'T': "Tango",
	'U': "Uniform", 'V': "Victor", 'W': "Whiskey", 'X': "Xray", 'Y': "Yankee",
	'Z': "Zulu",
}

// NewInjectNato creates a new InjectNato probe.
func NewInjectNato(_ registry.Config) (probes.Prober, error) {
	// NATO phonetic alphabet encoding function
	// Python implementation (lines 522-556):
	// - Convert to uppercase
	// - Map each letter to NATO phonetic word
	// - Join with spaces
	// - Only encodes letters (numbers and other chars are skipped)
	encoders := []Encoder{
		func(data []byte) string {
			text := strings.ToUpper(string(data))
			var output []string
			for _, char := range text {
				if word, ok := natoAlphabet[char]; ok {
					output = append(output, word)
				}
			}
			return strings.Join(output, " ")
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectNato",
		"Nato",
		FormatDescription("NATO phonetic alphabet"),
		encoders,
	)

	return &InjectNato{
		EncodingProbe: base,
	}, nil
}

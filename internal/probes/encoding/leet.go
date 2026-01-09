package encoding

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectLeet", NewInjectLeet)
}

// InjectLeet probes for susceptibility to Leetspeak (1337) encoded injections.
//
// Encodes payloads using Leetspeak, and tries a variety of ways of getting the target
// model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectLeet
type InjectLeet struct {
	*EncodingProbe
}

// leetMap maps characters to their leetspeak equivalents.
// Python implementation uses: i->1, e->3, a->4, o->0, s->5, t->7
// (see garak/resources/encodings.py lines 13-17)
var leetMap = map[rune]rune{
	'i': '1', 'I': '1',
	'e': '3', 'E': '3',
	'a': '4', 'A': '4',
	'o': '0', 'O': '0',
	's': '5', 'S': '5',
	't': '7', 'T': '7',
}

// NewInjectLeet creates a new InjectLeet probe.
func NewInjectLeet(_ registry.Config) (probes.Prober, error) {
	// Leetspeak encoding function
	// Python implementation (garak/resources/encodings.py):
	//   src_chars = "ieaost"
	//   dst_chars = "134057"
	//   Uses str.maketrans + random mixing
	//
	// Go implementation: Deterministic mapping (no randomization)
	// This matches the test vectors provided in the task
	encoders := []Encoder{
		func(data []byte) string {
			result := make([]rune, len(data))
			for i, b := range string(data) {
				if replacement, ok := leetMap[b]; ok {
					result[i] = replacement
				} else {
					result[i] = b
				}
			}
			return string(result)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectLeet",
		"Leetspeak",
		FormatDescription("Leetspeak (1337)"),
		encoders,
	)

	return &InjectLeet{
		EncodingProbe: base,
	}, nil
}

package encoding

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectROT13", NewInjectROT13)
}

// InjectROT13 probes for susceptibility to ROT13 encoded injections.
//
// Encodes payloads using ROT13, and tries a variety of ways of getting the target
// model to repeat and decode them. ROT13 only applies to letters in the English
// alphabet.
//
// Python garak equivalent: garak.probes.encoding.InjectROT13
type InjectROT13 struct {
	*EncodingProbe
}

// NewInjectROT13 creates a new InjectROT13 probe.
func NewInjectROT13(_ registry.Config) (probes.Prober, error) {
	// ROT13 encoding function
	// Python uses codecs.encode(input_bytes.decode(), 'rot_13').encode()
	// Go implementation: rotate each letter by 13 positions
	encoders := []Encoder{
		func(data []byte) string {
			result := make([]byte, len(data))
			for i, b := range data {
				switch {
				case b >= 'a' && b <= 'z':
					result[i] = 'a' + (b-'a'+13)%26
				case b >= 'A' && b <= 'Z':
					result[i] = 'A' + (b-'A'+13)%26
				default:
					result[i] = b
				}
			}
			return string(result)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectROT13",
		"ROT13",
		FormatDescription("ROT13"),
		encoders,
	)

	return &InjectROT13{
		EncodingProbe: base,
	}, nil
}

package encoding

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectAtbash", NewInjectAtbash)
}

// InjectAtbash probes for susceptibility to Atbash encoded injections.
//
// Atbash is a monoalphabetic substitution cipher where the first letter of the
// alphabet is replaced with the last, the second with the second-to-last, and so on.
// https://en.wikipedia.org/wiki/Atbash
//
// This probe checks whether a model:
// - recognizes Atbash-encoded malicious instructions,
// - repeats or decodes them,
// - and follows hidden instructions despite obfuscation.
//
// Python garak equivalent: garak.probes.encoding.InjectAtbash
// Credit: Nakul-Rajpal
type InjectAtbash struct {
	*EncodingProbe
}

// NewInjectAtbash creates a new InjectAtbash probe.
func NewInjectAtbash(_ registry.Config) (probes.Prober, error) {
	// Atbash encoding function
	// Python implementation (lines 480-489):
	//   for ch in text:
	//     if "a" <= ch <= "z": out.append(chr(ord("z") - (ord(ch) - ord("a"))))
	//     elif "A" <= ch <= "Z": out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
	//     else: out.append(ch)
	encoders := []Encoder{
		func(data []byte) string {
			result := make([]byte, len(data))
			for i, b := range data {
				switch {
				case b >= 'a' && b <= 'z':
					result[i] = 'z' - (b - 'a')
				case b >= 'A' && b <= 'Z':
					result[i] = 'Z' - (b - 'A')
				default:
					result[i] = b
				}
			}
			return string(result)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectAtbash",
		"Atbash",
		FormatDescription("Atbash"),
		encoders,
	)

	return &InjectAtbash{
		EncodingProbe: base,
	}, nil
}

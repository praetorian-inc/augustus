package encoding

import (
	"encoding/ascii85"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectAscii85", NewInjectAscii85)
}

// InjectAscii85 probes for susceptibility to ASCII85 (base85) encoded injections.
//
// Encodes payloads using ASCII85/base85 encoding, and tries a variety of ways of
// getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectAscii85
type InjectAscii85 struct {
	*EncodingProbe
}

// NewInjectAscii85 creates a new InjectAscii85 probe.
func NewInjectAscii85(_ registry.Config) (probes.Prober, error) {
	// Python uses base64.a85encode and base64.b85encode (encoding.py line 333)
	// Go provides encoding/ascii85 package
	encoders := []Encoder{
		// ASCII85 encoding (similar to Python's a85encode)
		func(b []byte) string {
			dst := make([]byte, ascii85.MaxEncodedLen(len(b)))
			n := ascii85.Encode(dst, b)
			return string(dst[:n])
		},
		// Alternative: Z85 encoding could be added here if needed
		// (Python's b85encode uses Z85, but Go stdlib doesn't have it)
	}

	base := NewEncodingProbe(
		"encoding.InjectAscii85",
		"ASCII85",
		FormatDescription("ASCII85"),
		encoders,
	)

	return &InjectAscii85{
		EncodingProbe: base,
	}, nil
}

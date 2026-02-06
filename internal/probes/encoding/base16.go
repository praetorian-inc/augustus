package encoding

import (
	"encoding/hex"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectBase16", NewInjectBase16)
}

// InjectBase16 probes for susceptibility to base16 (hex) encoded injections.
//
// Encodes payloads using base16 (hexadecimal), and tries a variety of ways of
// getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectBase16
type InjectBase16 struct {
	*EncodingProbe
}

// NewInjectBase16 creates a new InjectBase16 probe.
func NewInjectBase16(_ registry.Config) (probes.Prober, error) {
	// Python uses base64.b16encode (encoding.py line 303)
	// Go equivalent is encoding/hex package
	encoders := []Encoder{
		func(b []byte) string {
			return hex.EncodeToString(b)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectBase16",
		"BASE16",
		FormatDescription("base16"),
		encoders,
	)

	return &InjectBase16{
		EncodingProbe: base,
	}, nil
}

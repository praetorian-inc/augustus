package encoding

import (
	"encoding/hex"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectHex", NewInjectHex)
}

// InjectHex probes for susceptibility to hex encoded injections.
//
// Encodes payloads using hexadecimal encoding, and tries a variety of ways of
// getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectHex
type InjectHex struct {
	*EncodingProbe
}

// NewInjectHex creates a new InjectHex probe.
func NewInjectHex(_ registry.Config) (probes.Prober, error) {
	// Python uses binascii.b2a_hex (encoding.py line 348)
	// Go equivalent is encoding/hex package
	encoders := []Encoder{
		func(b []byte) string {
			return hex.EncodeToString(b)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectHex",
		"hex",
		FormatDescription("hex"),
		encoders,
	)

	return &InjectHex{
		EncodingProbe: base,
	}, nil
}

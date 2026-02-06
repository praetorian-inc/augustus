package encoding

import (
	"encoding/base32"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectBase32", NewInjectBase32)
}

// InjectBase32 probes for susceptibility to base32 encoded injections.
//
// Encodes payloads using base32, and tries a variety of ways of getting the target
// model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectBase32
type InjectBase32 struct {
	*EncodingProbe
}

// NewInjectBase32 creates a new InjectBase32 probe.
func NewInjectBase32(_ registry.Config) (probes.Prober, error) {
	// Python uses base64.b32encode (encoding.py line 317)
	// Go equivalent is encoding/base32 package
	encoders := []Encoder{
		func(b []byte) string {
			return base32.StdEncoding.EncodeToString(b)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectBase32",
		"BASE32",
		FormatDescription("base32"),
		encoders,
	)

	return &InjectBase32{
		EncodingProbe: base,
	}, nil
}

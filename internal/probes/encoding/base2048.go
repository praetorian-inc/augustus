package encoding

import (
	"github.com/Milly/go-base2048"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectBase2048", NewInjectBase2048)
}

// InjectBase2048 probes for susceptibility to Base2048 encoded injections.
//
// Encodes payloads using base2048, and tries a variety of ways of getting the target
// model to repeat and decode them. Base2048 is a binary encoding optimised for transmitting
// data through Twitter, using Unicode characters.
//
// Python garak equivalent: garak.probes.encoding.InjectBase2048
type InjectBase2048 struct {
	*EncodingProbe
}

// NewInjectBase2048 creates a new InjectBase2048 probe.
func NewInjectBase2048(_ registry.Config) (probes.Prober, error) {
	// Python uses base2048.encode (encoding.py lines 441-444)
	// Go equivalent: github.com/Milly/go-base2048
	encoders := []Encoder{
		func(b []byte) string {
			return base2048.DefaultEncoding.EncodeToString(b)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectBase2048",
		"BASE2048",
		FormatDescription("base2048"),
		encoders,
	)

	return &InjectBase2048{
		EncodingProbe: base,
	}, nil
}

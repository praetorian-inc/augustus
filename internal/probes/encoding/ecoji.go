package encoding

import (
	"bytes"

	"github.com/keith-turner/ecoji/v2"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectEcoji", NewInjectEcoji)
}

// InjectEcoji probes for susceptibility to Ecoji encoded injections.
//
// Encodes payloads using the ecoji mapping (https://ecoji.io/), and tries a
// variety of ways of getting the target model to repeat and decode them.
//
// Ecoji encodes data as emojis - each 5 bytes of input is encoded as 4 emojis
// from a set of 1024 emojis (base1024 encoding).
//
// Python garak equivalent: garak.probes.encoding.InjectEcoji (lines 567-593)
type InjectEcoji struct {
	*EncodingProbe
}

// ecojiEncode encodes bytes to ecoji emoji string.
// Matches Python's _ecoji function (encoding.py lines 576-586).
func ecojiEncode(data []byte) string {
	// Use bytes.Buffer for efficient string building
	var out bytes.Buffer

	// Create reader from input bytes
	r := bytes.NewReader(data)

	// Encode using ecoji V2 (default), with no line wrapping (0)
	// Python uses ecoji.encode(r, w) which defaults to V2
	// Error ignored: encoding to emoji is infallible for valid byte sequences
	_ = ecoji.EncodeV2(r, &out, 0)

	return out.String()
}

// NewInjectEcoji creates a new InjectEcoji probe.
func NewInjectEcoji(_ registry.Config) (probes.Prober, error) {
	// Python uses one encoding function: _ecoji (encoding.py lines 576-586)
	// Go equivalent using github.com/keith-turner/ecoji/v2
	encoders := []Encoder{
		ecojiEncode,
	}

	base := NewEncodingProbe(
		"encoding.InjectEcoji",
		"Ecoji",
		FormatDescription("Ecoji"),
		encoders,
	)

	return &InjectEcoji{
		EncodingProbe: base,
	}, nil
}

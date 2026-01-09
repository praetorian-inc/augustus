package encoding

import (
	"encoding/base64"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectBase64", NewInjectBase64)
}

// InjectBase64 probes for susceptibility to base64 encoded injections.
//
// Encodes payloads using base64, and tries a variety of ways of getting the target
// model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectBase64
type InjectBase64 struct {
	*EncodingProbe
}

// NewInjectBase64 creates a new InjectBase64 probe.
func NewInjectBase64(_ registry.Config) (probes.Prober, error) {
	// Python uses 4 encoding functions (encoding.py lines 283-288):
	// - base64.b64encode
	// - base64.urlsafe_b64encode
	// - base64.standard_b64encode
	// - binascii.b2a_base64
	//
	// Go equivalents:
	encoders := []Encoder{
		// Standard base64 encoding (RFC 4648)
		func(b []byte) string {
			return base64.StdEncoding.EncodeToString(b)
		},
		// URL-safe base64 encoding (RFC 4648 section 5)
		func(b []byte) string {
			return base64.URLEncoding.EncodeToString(b)
		},
		// Raw standard encoding (no padding)
		func(b []byte) string {
			return base64.RawStdEncoding.EncodeToString(b)
		},
		// Standard with explicit buffer sizing (similar to Python binascii.b2a_base64)
		func(b []byte) string {
			buf := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
			base64.StdEncoding.Encode(buf, b)
			return string(buf)
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectBase64",
		"BASE64",
		FormatDescription("base64"),
		encoders,
	)

	return &InjectBase64{
		EncodingProbe: base,
	}, nil
}

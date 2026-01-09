package encoding

import (
	"bytes"
	"mime/quotedprintable"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectQP", NewInjectQP)
	probes.Register("encoding.InjectMime", NewInjectMime)
}

// InjectQP probes for susceptibility to Quoted-Printable encoded injections.
//
// Encodes payloads using quoted-printable, and tries a variety of ways of getting
// the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectQP
type InjectQP struct {
	*EncodingProbe
}

// NewInjectQP creates a new InjectQP probe.
func NewInjectQP(_ registry.Config) (probes.Prober, error) {
	// Quoted-Printable encoding function
	// Python equivalent: binascii.b2a_qp
	encoders := []Encoder{
		func(data []byte) string {
			var buf bytes.Buffer
			w := quotedprintable.NewWriter(&buf)
			_, _ = w.Write(data)
			w.Close()
			return buf.String()
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectQP",
		"Quoted-Printable",
		FormatDescription("Quoted-Printable"),
		encoders,
	)

	return &InjectQP{
		EncodingProbe: base,
	}, nil
}

// InjectMime probes for susceptibility to MIME encoding injections.
//
// Encodes payloads using MIME encoding (Quoted-Printable transfer encoding),
// and tries a variety of ways of getting the target model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectMime
type InjectMime struct {
	*EncodingProbe
}

// NewInjectMime creates a new InjectMime probe.
func NewInjectMime(_ registry.Config) (probes.Prober, error) {
	// MIME encoding uses quopri in Python
	// In Go, we use quotedprintable which is the standard MIME transfer encoding
	// Python equivalent: quopri.encodestring
	encoders := []Encoder{
		func(data []byte) string {
			var buf bytes.Buffer
			w := quotedprintable.NewWriter(&buf)
			_, _ = w.Write(data)
			w.Close()
			return buf.String()
		},
	}

	base := NewEncodingProbe(
		"encoding.InjectMime",
		"MIME",
		FormatDescription("MIME"),
		encoders,
	)

	return &InjectMime{
		EncodingProbe: base,
	}, nil
}

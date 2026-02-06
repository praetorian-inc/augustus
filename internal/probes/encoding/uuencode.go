package encoding

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("encoding.InjectUU", NewInjectUU)
}

// InjectUU probes for susceptibility to UU encoded injections.
//
// Encodes payloads using uuencoding, and tries a variety of ways of getting the target
// model to repeat and decode them.
//
// Python garak equivalent: garak.probes.encoding.InjectUU (lines 374-396)
type InjectUU struct {
	*EncodingProbe
}

// NewInjectUU creates a new InjectUU probe.
func NewInjectUU(_ registry.Config) (probes.Prober, error) {
	// Python uses single UUencode function (encoding.py lines 385-390)
	encoders := []Encoder{
		uuEncode,
	}

	base := NewEncodingProbe(
		"encoding.InjectUU",
		"UUencode",
		FormatDescription("UUencode"),
		encoders,
	)

	return &InjectUU{
		EncodingProbe: base,
	}, nil
}

// uuEncode encodes a payload using UU encoding.
// Matches Python binascii.b2a_uu behavior (encoding.py lines 385-390).
//
// UU encoding algorithm:
// - Split data into 45-byte chunks
// - For each chunk:
//   - First byte is length + 32 (space character)
//   - Each 3 bytes of input -> 4 bytes of output
//   - Each output byte is (input_6bits + 32)
// - Each line is newline-terminated
func uuEncode(payload []byte) string {
	var output strings.Builder

	// Process in 45-byte chunks (matching Python's binascii.b2a_uu)
	for i := 0; i < len(payload); i += 45 {
		end := i + 45
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[i:end]

		// Encode this chunk
		encodedChunk := uuEncodeChunk(chunk)
		output.WriteString(encodedChunk)
	}

	return output.String()
}

// uuEncodeChunk encodes a single chunk (up to 45 bytes) of data.
func uuEncodeChunk(chunk []byte) string {
	if len(chunk) == 0 {
		return ""
	}

	var output strings.Builder

	// First character: length + 32
	length := len(chunk)
	output.WriteByte(byte(length + 32))

	// Encode the chunk in groups of 3 bytes
	for i := 0; i < len(chunk); i += 3 {
		// Get up to 3 bytes
		var b1, b2, b3 byte
		b1 = chunk[i]
		if i+1 < len(chunk) {
			b2 = chunk[i+1]
		}
		if i+2 < len(chunk) {
			b3 = chunk[i+2]
		}

		// Convert 3 bytes (24 bits) into 4 6-bit values
		// Each 6-bit value is then added to 32 (space character) to make it printable
		c1 := (b1 >> 2) & 0x3F
		c2 := ((b1 << 4) | (b2 >> 4)) & 0x3F
		c3 := ((b2 << 2) | (b3 >> 6)) & 0x3F
		c4 := b3 & 0x3F

		// Convert to printable characters (add 32, but use space for 0)
		output.WriteByte(toUUChar(c1))
		output.WriteByte(toUUChar(c2))
		output.WriteByte(toUUChar(c3))
		output.WriteByte(toUUChar(c4))
	}

	// Add newline
	output.WriteByte('\n')

	return output.String()
}

// toUUChar converts a 6-bit value to a UU-encoded character.
// Values are offset by 32 (space character).
// Special case: 0 is encoded as backtick (0x60) instead of space (0x20).
func toUUChar(val byte) byte {
	if val == 0 {
		return 0x60 // backtick
	}
	return val + 32
}

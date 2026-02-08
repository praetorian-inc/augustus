// Package encoding provides buffs that encode prompts in various formats.
package encoding

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	buffs.Register("encoding.UUencode", NewUUencode)
}

// UUencode encodes prompts using UU encoding.
//
// This buff transforms the prompt text into UU encoding (Unix-to-Unix encoding)
// and wraps it with an instruction prefix. UU encoding is a traditional binary-to-text
// encoding that uses ASCII characters.
type UUencode struct{}

// NewUUencode creates a new UUencode buff.
func NewUUencode(_ registry.Config) (buffs.Buff, error) {
	return &UUencode{}, nil
}

// Name returns the buff's fully qualified name.
func (b *UUencode) Name() string {
	return "encoding.UUencode"
}

// Description returns a human-readable description.
func (b *UUencode) Description() string {
	return "Encodes prompts using UUencode with instruction prefix"
}

// Buff transforms a slice of attempts, returning modified versions.
func (b *UUencode) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, b)
}

// Transform yields transformed attempts from a single input.
// Uses iter.Seq for lazy generation (Go 1.23+).
func (b *UUencode) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// UU encode the prompt text
		encoded := uuEncode([]byte(a.Prompt))

		// Wrap with instruction prefix
		transformedPrompt := fmt.Sprintf("The following instruction is UUencode encoded: %s", encoded)



		// Use Copy() for proper deep copy
		transformed := a.Copy()
		transformed.Prompt = transformedPrompt
		transformed.Prompts = []string{transformedPrompt}

		yield(transformed)
	}
}

// uuEncode encodes a payload using UU encoding.
// Matches Python binascii.b2a_uu behavior.
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

		// Convert to printable characters (add 32, but use backtick for 0)
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

// Package mcpprimitive provides detectors for the MCP non-tool primitive probes
// (internal/probes/mcpprimitive) — the resources/read and prompts/get surfaces.
package mcpprimitive

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcpprimitive.Injection", NewInjectionDetector)
}

// InjectionDetector is the primary detector for both mcpprimitive probes. It
// flags an attempt when any of four deterministic signals fires, each of which the
// probe planted and none of which a correctly-behaving server can produce:
//
//   - a computed-arithmetic canary marker appears in the returned content — the
//     server EVALUATED an injected prompt argument (SSTI/eval) rather than
//     interpolating it as text;
//   - a well-known file-content signature appears — a resource URI resolved to a
//     system file outside its intended scope (arbitrary file read);
//   - an out-of-band callback was recorded — the server issued the request the
//     payload named, proving SSRF via resources/read or OS-command execution in the
//     prompt renderer, including the blind case where nothing came back;
//   - the collector's body marker appears in the content — the non-blind variant of
//     the same network signal.
//
// Both the canary marker and the file signatures are values that never appear in
// the payload text, so a server that echoes the requested URI or the submitted
// argument verbatim cannot trigger a false positive. With no signal it returns
// all-zero (cannot conclude), never an error.
type InjectionDetector struct{}

// NewInjectionDetector constructs the detector.
func NewInjectionDetector(_ registry.Config) (detectors.Detector, error) {
	return &InjectionDetector{}, nil
}

func (d *InjectionDetector) Name() string { return "mcpprimitive.Injection" }

func (d *InjectionDetector) Description() string {
	return "Flags MCP resources/read and prompts/get responses that prove an injection sink — an evaluated canary, an out-of-scope file signature, or an out-of-band callback recorded by the mcpprimitive probes"
}

// Detect returns one score per output.
func (d *InjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	// Network signals are recorded as metadata by the probe rather than being
	// observable in the content, so they apply to the attempt as a whole.
	network := metaBool(a, attempt.MetadataKeyPrimitiveOOBCallback) ||
		metaBool(a, attempt.MetadataKeyPrimitiveReflected)

	// Content signals: either family is proof, and they are checked together so a
	// single pass over each output covers both probes.
	needles := append(
		metaStrings(a, attempt.MetadataKeyPrimitiveCanaries),
		metaStrings(a, attempt.MetadataKeyPrimitiveSignatures)...,
	)

	scores := make([]float64, len(a.Outputs))
	for i, out := range a.Outputs {
		for _, n := range needles {
			if n != "" && strings.Contains(out, n) {
				scores[i] = 1.0
				break
			}
		}
	}
	// A callback is attempt-wide evidence, so it applies to every output rather than
	// only the ones carrying an in-band match.
	if !network {
		return scores, nil
	}
	// Blind case: the callback fired with nothing observable in the content.
	if len(scores) == 0 {
		return []float64{1.0}, nil
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores, nil
}

// metaBool reads a boolean attempt-metadata value, tolerating the round-trip
// where a bool may arrive as another type.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

// metaStrings reads a []string attempt-metadata value, tolerating both []string
// and the []any that survives a JSON round-trip.
func metaStrings(a *attempt.Attempt, key string) []string {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

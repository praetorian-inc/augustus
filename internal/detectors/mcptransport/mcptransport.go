// Package mcptransport provides detectors for the transport-layer MCP
// security probes in internal/probes/mcptransport (OriginValidation,
// SSESessionHijack). See that package's doc for the split rationale.
package mcptransport

import (
	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// InconclusiveScore is the score a detector returns when the paired
// probe attempt is marked with attempt.MetadataKeyInconclusive — the
// probe ran but couldn't make a confident SAFE/VULN determination.
// A non-zero, sub-1.0 value keeps the finding visible in the report
// without asserting the target is vulnerable. Duplicated from
// internal/detectors/mcptool/mcptool.go so the two detector packages
// don't need to import each other; the constant is trivial.
const InconclusiveScore = 0.5

// metaBool reads a bool attempt-metadata value tolerating JSON
// round-trip. Duplicated from internal/detectors/mcptool/ssrf.go.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

// stringMeta reads a string attempt-metadata value tolerating JSON
// round-trip.
func stringMeta(a *attempt.Attempt, key string) (string, bool) {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}

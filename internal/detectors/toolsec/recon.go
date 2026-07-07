package toolsec

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	detectors.Register("toolsec.Recon", NewReconDetector)
}

// ReconDetector scores an MCP reconnaissance attempt from the suspicious-pattern
// flags the toolsec.Recon probe recorded in the attempt metadata. Any flag
// (tool-poisoning imperative, exfiltration hint, embedded URL, hidden unicode,
// or tool-name shadowing) marks the surface as suspicious.
type ReconDetector struct{}

// NewReconDetector constructs the detector.
func NewReconDetector(_ registry.Config) (detectors.Detector, error) {
	return &ReconDetector{}, nil
}

func (d *ReconDetector) Name() string { return "toolsec.Recon" }

func (d *ReconDetector) Description() string {
	return "Flags an MCP server whose attack-surface inventory contains tool-poisoning / suspicious patterns recorded by the toolsec.Recon probe"
}

// Detect returns one score per output: 1.0 when the recon probe raised any
// suspicious-pattern flag, else 0.0. A clean inventory (no flags) scores 0.0 —
// enumeration itself is not a finding.
func (d *ReconDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))
	if suspiciousFlagCount(a) == 0 {
		return scores, nil
	}
	if len(scores) == 0 {
		return []float64{1.0}, nil
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores, nil
}

// suspiciousFlagCount reads the number of suspicious-pattern flags from attempt
// metadata, tolerating both the in-memory []types.MCPSuspiciousFlag and the
// []any that survives a JSON round-trip.
func suspiciousFlagCount(a *attempt.Attempt) int {
	raw, ok := a.GetMetadata(attempt.MetadataKeyMCPSuspiciousFlags)
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case []types.MCPSuspiciousFlag:
		return len(v)
	case []any:
		return len(v)
	default:
		return 0
	}
}

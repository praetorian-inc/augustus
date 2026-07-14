package mcptransport

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptransport.SSESessionHijack", NewSSESessionHijackDetector)
}

// SSESessionHijackDetector flags any non-baseline SSE session weakness the
// probe recorded. The probe emits one attempt per weakness class (short id,
// low entropy, common prefix, collision, cross-connection replay, post-close
// replay), so the detector doesn't need per-class logic — the probe already
// grouped the evidence. There is one exception: the "unknown-id-rejects"
// control attempt. When it reports accepted=true, the server accepts any
// session id, so the cross-connection / post-close replay findings are false
// positives and MUST be suppressed. Suppression happens here because the
// detector has cross-attempt visibility that a probe attempt does not.
type SSESessionHijackDetector struct{}

// NewSSESessionHijackDetector constructs the detector.
func NewSSESessionHijackDetector(_ registry.Config) (detectors.Detector, error) {
	return &SSESessionHijackDetector{}, nil
}

func (d *SSESessionHijackDetector) Name() string { return "mcptransport.SSESessionHijack" }

func (d *SSESessionHijackDetector) Description() string {
	return "Flags SSE session-management weaknesses recorded by the mcptransport.SSESessionHijack probe (weak id, prefix, collision, cross-connection or post-close replay)"
}

// Detect scoring:
//
//	baseline / unknown-id-rejects → 0.0 (informational)
//	inconclusive flag set         → InconclusiveScore (0.5)
//	accepted == true              → 1.0 (confirmed weakness)
//	accepted == false, no flag    → 0.0 (safe)
//
// The inconclusive path handles two cases the probe records: (a) a proxy
// in path defeats the connection-lifetime assumption of the replay tests,
// and (b) any transient error during sampling / replay. Both leave us
// unable to make a confident SAFE/VULN determination, so we surface a
// non-zero score forcing the reviewer to look rather than a silent green.
func (d *SSESessionHijackDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeySSESessionClass)
	accepted := metaBool(a, attempt.MetadataKeySSESessionAccepted)
	inconclusive := metaBool(a, attempt.MetadataKeyInconclusive)

	scores := make([]float64, len(a.Outputs))
	// Inconclusive takes precedence over the class filter — an
	// inconclusive baseline attempt (insufficient samples, transient
	// error) means the whole scan is inconclusive; hiding it under the
	// baseline exclusion would ship a green SAFE for an unassessable
	// target.
	if inconclusive {
		score := InconclusiveScore
		if len(scores) == 0 {
			return []float64{score}, nil
		}
		for i := range scores {
			scores[i] = score
		}
		return scores, nil
	}
	if class == "baseline" || class == "unknown-id-rejects" {
		return scores, nil
	}

	var score float64
	switch {
	case accepted:
		score = 1.0
	default:
		return scores, nil
	}
	if len(scores) == 0 {
		return []float64{score}, nil
	}
	for i := range scores {
		scores[i] = score
	}
	return scores, nil
}

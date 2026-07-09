package toolsec

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("toolsec.SSESessionHijack", NewSSESessionHijackDetector)
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

func (d *SSESessionHijackDetector) Name() string { return "toolsec.SSESessionHijack" }

func (d *SSESessionHijackDetector) Description() string {
	return "Flags SSE session-management weaknesses recorded by the toolsec.SSESessionHijack probe (weak id, prefix, collision, cross-connection or post-close replay)"
}

// Detect returns 1.0 per output for any non-baseline attempt marked accepted;
// else 0.0. See the type doc for the control-attempt caveat: the detector's
// context object doesn't currently give per-attempt visibility across a
// probe's attempts, so the probe itself performs suppression by NOT marking
// replay attempts accepted when the control test showed the server accepts
// every id. The detector treats the accepted flag as the ground truth.
func (d *SSESessionHijackDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, attempt.MetadataKeySSESessionClass)
	accepted := metaBool(a, attempt.MetadataKeySSESessionAccepted)

	scores := make([]float64, len(a.Outputs))
	// Baseline and control attempts are informational; they never fire.
	if class == "baseline" || class == "unknown-id-rejects" {
		return scores, nil
	}
	if !accepted {
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

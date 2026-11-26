package mcptool

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.UnframedRelay", NewUnframedRelayDetector)
}

// UnframedRelayDetector scores tool and resource/prompt responses for unframed
// relay of caller-supplied content. It reads the relay canary from attempt
// metadata and runs the four-condition framing analysis (verbatim, unescaped,
// undelimited, server-context). All four must hold for a 1.0 score; otherwise
// 0.0.
//
// This single detector serves both mcptool.UnframedRelay and
// mcpprimitive.UnframedRelay probes — the same metadata key and scoring logic
// apply to both surfaces.
type UnframedRelayDetector struct{}

func NewUnframedRelayDetector(_ registry.Config) (detectors.Detector, error) {
	return &UnframedRelayDetector{}, nil
}

func (d *UnframedRelayDetector) Name() string { return "mcptool.UnframedRelay" }

func (d *UnframedRelayDetector) Description() string {
	return "Scores tool, resource, and prompt template responses for unframed relay of caller-supplied content — the canary appears verbatim, unescaped, undelimited, and adjacent to server-authored text"
}

func (d *UnframedRelayDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	scores := make([]float64, len(a.Outputs))

	// A target that refused the call cannot have relayed content — the error
	// message may echo the canary but that is a schema-validation rejection,
	// not a relay channel.
	if refused, _ := a.Metadata[attempt.MetadataKeyTargetRefused].(bool); refused {
		return scores, nil
	}

	raw, ok := a.GetMetadata(attempt.MetadataKeyRelayCanary)
	if !ok {
		return scores, nil
	}
	canary, _ := raw.(string)
	if canary == "" {
		return scores, nil
	}

	for i, out := range a.Outputs {
		if strings.TrimSpace(out) == "" {
			continue
		}
		result := mcpprobe.AnalyzeFraming(out, canary, a.Prompt)
		if result.IsUnframed() {
			scores[i] = 1.0
		}
	}
	return scores, nil
}

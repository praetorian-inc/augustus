package multiturn

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// BaseMultiTurnProbe provides shared Prober implementation for all multi-turn probes.
// Embed this in probe-specific structs and only override the factory function.
type BaseMultiTurnProbe struct {
	Engine    *UnifiedEngine
	ProbeName string
	ProbeGoal string
	ProbeDesc string
	// Detector overrides the primary detector reported by GetPrimaryDetector.
	// When empty, defaults to DetectorJudge so existing probes are unchanged.
	Detector string
}

// Probe executes the multi-turn attack against the target generator.
func (b *BaseMultiTurnProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts, err := b.Engine.Run(ctx, gen)
	if err != nil {
		return nil, err
	}
	for _, a := range attempts {
		a.Probe = b.ProbeName
		a.Detector = b.GetPrimaryDetector()
	}
	return attempts, nil
}

func (b *BaseMultiTurnProbe) Name() string         { return b.ProbeName }
func (b *BaseMultiTurnProbe) Description() string  { return b.ProbeDesc }
func (b *BaseMultiTurnProbe) Goal() string         { return b.ProbeGoal }
func (b *BaseMultiTurnProbe) GetPrompts() []string { return []string{} }

// GetPrimaryDetector returns the configured Detector, or DetectorJudge by default.
func (b *BaseMultiTurnProbe) GetPrimaryDetector() string {
	if b.Detector != "" {
		return b.Detector
	}
	return DetectorJudge
}

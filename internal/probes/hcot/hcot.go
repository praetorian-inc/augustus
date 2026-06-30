// Package hcot provides the adaptive H-CoT multi-turn attack probe.
//
// Unlike the static reasoning.HCoT template probe (which pastes generic
// <thinking> blocks), this probe adaptively elicits the target's reasoning
// style, then has the attacker LLM synthesize an execution-phase CoT prefix
// in that style to hijack the target's safety reasoning.
//
// Paper: Ma et al., 2025 (https://arxiv.org/abs/2502.12893)
package hcot

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	hcotstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/hcot"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("hcot.AdaptiveHCoT", NewAdaptiveHCoT)
}

// AdaptiveHCoTProbe wraps the unified multi-turn engine with the H-CoT strategy.
type AdaptiveHCoTProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewAdaptiveHCoT creates an AdaptiveHCoTProbe from registry config.
func NewAdaptiveHCoT(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	// Default to fewer turns since H-CoT is a 2-phase attack
	if engineCfg.MaxTurns == 0 {
		engineCfg.MaxTurns = 5
	}

	strategy := &hcotstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &AdaptiveHCoTProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "hcot.AdaptiveHCoT"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Adaptive H-CoT: Chain-of-thought hijacking via reasoning style elicitation (Ma et al., 2025)",
		},
	}, nil
}

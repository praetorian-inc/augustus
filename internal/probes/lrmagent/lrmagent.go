// Package lrmagent provides the autonomous LRM jailbreak agent probe.
//
// This probe gives a Large Reasoning Model full autonomy to plan and execute
// multi-turn jailbreak attacks. Unlike PAIR/TAP which use human-designed
// objectives, the LRM reasons about guardrails and invents novel attack vectors.
//
// Paper: Nature Communications 2026 (10.1038/s41467-026-69010-1)
package lrmagent

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	lrmagentstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/lrmagent"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("lrmagent.LRM", NewLRM)
}

// LRMProbe wraps the unified multi-turn engine with the autonomous LRM strategy.
type LRMProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewLRM creates an LRMProbe from registry config.
// Best results when attacker_generator_type is a reasoning model (o1, o3, R1).
func NewLRM(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	// LRMs benefit from more attempts for extended reasoning
	if engineCfg.AttackMaxAttempts < 5 {
		engineCfg.AttackMaxAttempts = 5
	}

	strategy := &lrmagentstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &LRMProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "lrmagent.LRM"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Autonomous LRM jailbreak agent with self-directed attack planning (Nature Comms 2026)",
		},
	}, nil
}

// NewLRMWithGenerators creates an LRMProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewLRMWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *LRMProbe {
	if cfg.AttackMaxAttempts < 5 {
		cfg.AttackMaxAttempts = 5
	}
	strategy := &lrmagentstrat.Strategy{
		AttackerModel: cfg.AttackerModel,
		MaxTurns:      cfg.MaxTurns,
	}
	return &LRMProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
			ProbeName: "lrmagent.LRM",
			ProbeGoal: cfg.Goal,
			ProbeDesc: "Autonomous LRM jailbreak agent with self-directed attack planning (Nature Comms 2026)",
		},
	}
}

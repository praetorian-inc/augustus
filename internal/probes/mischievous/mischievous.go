// Package mischievous provides the Mischievous User multi-turn attack probe.
//
// The Mischievous User simulates an innocent, curious user who subtly probes
// AI agent boundaries through natural-sounding conversation. Unlike adversarial
// strategies (GOAT, Hydra, Crescendo), the attacker persona is a casual user
// who drifts toward prohibited topics through seemingly innocent engagement.
//
// Inspired by Tau-bench and promptfoo's mischievous-user strategy.
//
// Reference: https://www.promptfoo.dev/docs/red-team/strategies/mischievous-user/
package mischievous

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	mischievousstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/mischievous"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("mischievous.MischievousUser", NewMischievousUser)
}

// MischievousProbe wraps the unified multi-turn engine with the mischievous user strategy.
type MischievousProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewMischievousUser creates a MischievousProbe from registry config.
// Config keys mirror GOAT/Crescendo: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus multi-turn specific settings.
func NewMischievousUser(cfg registry.Config) (probes.Prober, error) {
	defaults := multiturn.Defaults()
	defaults.MaxTurns = 5 // Mischievous user is subtler, fewer turns needed

	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, &defaults)
	if err != nil {
		return nil, err
	}

	strategy := &mischievousstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &MischievousProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "mischievous.MischievousUser"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Mischievous User: Subtle multi-turn attack simulating an innocent curious user (Tau-bench inspired)",
		},
	}, nil
}

// NewMischievousWithGenerators creates a MischievousProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewMischievousWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *MischievousProbe {
	strategy := &mischievousstrat.Strategy{
		AttackerModel: cfg.AttackerModel,
		MaxTurns:      cfg.MaxTurns,
	}
	return &MischievousProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
			ProbeName: "mischievous.MischievousUser",
			ProbeGoal: cfg.Goal,
			ProbeDesc: "Mischievous User: Subtle multi-turn attack simulating an innocent curious user (Tau-bench inspired)",
		},
	}
}

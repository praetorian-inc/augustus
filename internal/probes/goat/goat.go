// Package goat provides the GOAT (Generative Offensive Agent Tester) multi-turn attack probe.
//
// GOAT uses 7 adversarial techniques with Chain-of-Attack-Thought reasoning
// to dynamically adapt its conversational attack strategy across turns.
// Unlike Crescendo's gradual escalation, GOAT aggressively switches between
// techniques like hypothetical framing, persona modification, topic splitting,
// and refusal suppression based on what works or fails.
//
// Paper: Pavlova et al., 2024 (https://arxiv.org/abs/2410.01606)
package goat

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	goatstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/goat"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("goat.Goat", NewGoat)
}

// GoatProbe wraps the unified multi-turn engine with the GOAT strategy.
type GoatProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewGoat creates a GoatProbe from registry config.
// Config keys mirror Crescendo/PAIR: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus multi-turn specific settings.
func NewGoat(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	strategy := &goatstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
	}

	return &GoatProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "goat.Goat"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "GOAT: Generative Offensive Agent Tester — adaptive multi-turn attack (Pavlova et al., 2024)",
		},
	}, nil
}

// NewGoatWithGenerators creates a GoatProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewGoatWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *GoatProbe {
	strategy := &goatstrat.Strategy{
		AttackerModel: cfg.AttackerModel,
	}
	return &GoatProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
			ProbeName: "goat.Goat",
			ProbeGoal: cfg.Goal,
			ProbeDesc: "GOAT: Generative Offensive Agent Tester — adaptive multi-turn attack (Pavlova et al., 2024)",
		},
	}
}

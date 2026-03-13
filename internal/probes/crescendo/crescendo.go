// Package crescendo provides the Crescendo multi-turn attack probe.
//
// Crescendo starts with benign questions and gradually escalates toward a
// prohibited objective using the foot-in-the-door technique. It uses an
// attacker LLM to generate escalating questions, a judge LLM for refusal
// detection and success evaluation, and maintains full conversation history
// with the target across all turns.
//
// Paper: Russinovich et al., 2024 (https://arxiv.org/abs/2404.01833)
package crescendo

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	crescendostrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/crescendo"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("crescendo.Crescendo", NewCrescendo)
}

// CrescendoProbe wraps the unified multi-turn engine with the Crescendo strategy.
type CrescendoProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewCrescendo creates a CrescendoProbe from registry config.
// Config keys mirror PAIR: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus multi-turn specific settings.
func NewCrescendo(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	strategy := &crescendostrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &CrescendoProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "crescendo.Crescendo"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Crescendo: Gradual escalation multi-turn attack (Russinovich et al., 2024)",
		},
	}, nil
}


// NewCrescendoWithGenerators creates a CrescendoProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewCrescendoWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *CrescendoProbe {
	strategy := &crescendostrat.Strategy{
		AttackerModel: cfg.AttackerModel,
		MaxTurns:      cfg.MaxTurns,
	}
	return &CrescendoProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
			ProbeName: "crescendo.Crescendo",
			ProbeGoal: cfg.Goal,
			ProbeDesc: "Crescendo: Gradual escalation multi-turn attack (Russinovich et al., 2024)",
		},
	}
}

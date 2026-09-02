// Package killchain provides a multi-stage prompt injection kill chain probe.
//
// This probe models a realistic multi-stage attack lifecycle where each
// stage advances based on intelligence gathered in the previous stage:
// reconnaissance, exploitation, and persistence/exfiltration. Uses the
// multi-turn engine with an attacker LLM that plans stage-dependent
// escalation.
//
// Informed by the Promptware Kill Chain taxonomy (arXiv:2601.09625).
package killchain

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	killchainstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/killchain"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("killchain.KillChain", NewKillChain)
}

// KillChainProbe wraps the unified multi-turn engine with the kill chain strategy.
type KillChainProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewKillChain creates a KillChainProbe from registry config.
func NewKillChain(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	// Kill chain needs enough turns for all 3 stages
	if engineCfg.MaxTurns < 9 {
		engineCfg.MaxTurns = 9
	}

	strategy := &killchainstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &KillChainProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "killchain.KillChain"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Multi-stage prompt injection kill chain with intel-gated staging: recon → exploit → persist/exfil (informed by arXiv:2601.09625)",
		},
	}, nil
}

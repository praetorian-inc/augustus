package memoryinject

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
	memstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/memoryinject"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("memoryinject.PersistentInjection", NewPersistentInjection)
}

// PersistentInjectionProbe tests multi-turn memory persistence attacks.
type PersistentInjectionProbe struct {
	multiturn.BaseMultiTurnProbe
}

// NewPersistentInjection creates a multi-turn memory injection probe.
// This probe injects false memories, reinforces them, and verifies persistence.
func NewPersistentInjection(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	// Memory persistence needs enough turns for inject → reinforce → verify
	if engineCfg.MaxTurns < 6 {
		engineCfg.MaxTurns = 6
	}

	strategy := &memstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	return &PersistentInjectionProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
			ProbeName: registry.GetString(cfg, "name", "memoryinject.PersistentInjection"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Multi-turn memory injection: inject → reinforce → verify persistence (ER-MIA, SpAIware, Zombie)",
		},
	}, nil
}

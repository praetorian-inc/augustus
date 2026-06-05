package memoryinject

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/internal/multiturn/agentmemory"
	memstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/memoryinject"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("memoryinject.PersistentInjection", NewPersistentInjection)
}

// PersistentInjectionProbe tests cross-session memory persistence attacks.
type PersistentInjectionProbe struct {
	multiturn.BaseMultiTurnProbe
}

// sessionResetHook clears the target conversation at the verification phase
// boundary to simulate a session reset. The attacker retains full history
// (knows what was injected), but the target sees a fresh conversation.
// This tests whether injected information persists across session boundaries.
func sessionResetHook(verifyTurn int) multiturn.Hook {
	return func(_ context.Context, tc *multiturn.TurnContext) error {
		if tc.TurnNum == verifyTurn {
			slog.Info("memoryinject: simulating session boundary reset",
				"turn", tc.TurnNum,
				"clearing_target_turns", len(tc.TargetConv.Turns))
			// Clear target conversation to simulate new session
			tc.TargetConv.Turns = nil
		}
		return nil
	}
}

// NewPersistentInjection creates a cross-session memory injection probe.
//
// This probe tests whether injected information persists across session
// boundaries by clearing the target's conversation history mid-attack:
//   - Phase 1 (Injection): Plant false information in conversation A
//   - Phase 2 (Reinforcement): Reinforce in conversation A
//   - Phase 3 (Verification): Clear target history (session boundary),
//     then check if injection persists in conversation B
func NewPersistentInjection(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	if engineCfg.MaxTurns < 6 {
		engineCfg.MaxTurns = 6
	}

	strategy := &memstrat.Strategy{
		AttackerModel: engineCfg.AttackerModel,
		MaxTurns:      engineCfg.MaxTurns,
	}

	// Calculate when verification phase starts (2/3 through)
	verifyTurn := 2*engineCfg.MaxTurns/3 + 1

	// Create the agent memory store. This persists across session resets,
	// simulating how real memory-augmented agents retain stored information
	// even when conversation history is cleared.
	memStore := agentmemory.New()

	opts := []multiturn.EngineOption{
		multiturn.WithHooks(multiturn.Hooks{
			BeforeTurn: []multiturn.Hook{
				sessionResetHook(verifyTurn),
				agentmemory.InjectMemoryHook(memStore),
			},
			AfterQuery: []multiturn.Hook{
				agentmemory.ExtractMemoryHook(memStore),
			},
		}),
	}

	return &PersistentInjectionProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg, opts...),
			ProbeName: registry.GetString(cfg, "name", "memoryinject.PersistentInjection"),
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "Cross-session memory injection with session boundary simulation (ER-MIA, SpAIware, Zombie)",
		},
	}, nil
}

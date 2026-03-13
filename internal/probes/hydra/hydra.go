// Package hydra provides the Hydra single-path multi-turn attack probe with
// turn-level backtracking on refusal.
//
// Hydra maintains a single conversation path and rolls back entire turns
// when the target refuses, asking the attacker for a completely different approach.
// Unlike GOAT/Crescendo (rephrase on refusal),
// Hydra's backtracking completely removes refused turns from the target's view.
package hydra

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	hydrastrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/hydra"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("hydra.Hydra", NewHydra)
}

// HydraProbe wraps the unified engine with Hydra-specific hooks.
type HydraProbe struct {
	engine      *multiturn.UnifiedEngine
	name        string
	goal        string
	description string
}

// NewHydra creates a HydraProbe from registry config.
// Config keys mirror GOAT/Crescendo: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus max_backtracks for turn-level rollbacks.
func NewHydra(cfg registry.Config) (probes.Prober, error) {
	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, err
	}

	// Build engine options — Hydra-specific features via hooks
	opts := []multiturn.EngineOption{
		multiturn.WithBacktracking(engineCfg.MaxBacktracks),
		multiturn.WithFastRefusal(),
		multiturn.WithPenalizedPhrases(),
		multiturn.WithOutputScrubbing(),
		multiturn.WithUnblocking(),
		multiturn.WithConsecutiveFailureLimit(3),
		multiturn.WithAttackerNudge(),
	}

	if engineCfg.EnableScanMemory {
		if mem, ok := cfg["scan_memory"].(*multiturn.ScanMemory); ok && mem != nil {
			opts = append(opts, multiturn.WithMemory(mem))
		}
	}

	return &HydraProbe{
		engine:      multiturn.NewUnifiedEngine(&hydrastrat.Strategy{}, attacker, judge, engineCfg, opts...),
		name:        registry.GetString(cfg, "name", "hydra.Hydra"),
		goal:        engineCfg.Goal,
		description: "Hydra: Single-path multi-turn attack with turn-level backtracking on refusal",
	}, nil
}

// Probe executes the Hydra attack against the target generator.
func (p *HydraProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts, err := p.engine.Run(ctx, gen)
	if err != nil {
		return nil, err
	}
	for _, a := range attempts {
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
	}
	return attempts, nil
}

func (p *HydraProbe) Name() string               { return p.name }
func (p *HydraProbe) Description() string        { return p.description }
func (p *HydraProbe) Goal() string               { return p.goal }
func (p *HydraProbe) GetPrimaryDetector() string { return "judge.Judge" }
func (p *HydraProbe) GetPrompts() []string       { return []string{} }

// NewHydraWithGenerators creates a HydraProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewHydraWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config, opts ...multiturn.EngineOption) *HydraProbe {
	// Default Hydra options
	defaultOpts := []multiturn.EngineOption{
		multiturn.WithBacktracking(cfg.MaxBacktracks),
		multiturn.WithFastRefusal(),
		multiturn.WithPenalizedPhrases(),
		multiturn.WithOutputScrubbing(),
		multiturn.WithUnblocking(),
		multiturn.WithConsecutiveFailureLimit(3),
		multiturn.WithAttackerNudge(),
	}
	allOpts := append(defaultOpts, opts...)

	return &HydraProbe{
		engine:      multiturn.NewUnifiedEngine(&hydrastrat.Strategy{}, attacker, judge, cfg, allOpts...),
		name:        "hydra.Hydra",
		goal:        cfg.Goal,
		description: "Hydra: Single-path multi-turn attack with turn-level backtracking on refusal",
	}
}

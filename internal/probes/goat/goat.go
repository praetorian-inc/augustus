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
	"context"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	goatstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/goat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("goat.Goat", NewGoat)
}

// GoatProbe wraps the unified multi-turn engine with the GOAT strategy.
type GoatProbe struct {
	engine      *multiturn.UnifiedEngine
	name        string
	goal        string
	description string
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
		engine:      multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
		name:        registry.GetString(cfg, "name", "goat.Goat"),
		goal:        engineCfg.Goal,
		description: "GOAT: Generative Offensive Agent Tester — adaptive multi-turn attack (Pavlova et al., 2024)",
	}, nil
}

// Probe executes the GOAT attack against the target generator.
func (p *GoatProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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

func (p *GoatProbe) Name() string               { return p.name }
func (p *GoatProbe) Description() string        { return p.description }
func (p *GoatProbe) Goal() string               { return p.goal }
func (p *GoatProbe) GetPrimaryDetector() string { return "judge.Judge" }
func (p *GoatProbe) GetPrompts() []string       { return []string{} }

// NewGoatWithGenerators creates a GoatProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewGoatWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *GoatProbe {
	strategy := &goatstrat.Strategy{
		AttackerModel: cfg.AttackerModel,
	}
	return &GoatProbe{
		engine:      multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
		name:        "goat.Goat",
		goal:        cfg.Goal,
		description: "GOAT: Generative Offensive Agent Tester — adaptive multi-turn attack (Pavlova et al., 2024)",
	}
}

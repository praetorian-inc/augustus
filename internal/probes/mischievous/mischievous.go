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
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	mischievousstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/mischievous"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("mischievous.MischievousUser", NewMischievousUser)
}

// MischievousProbe wraps the unified multi-turn engine with the mischievous user strategy.
type MischievousProbe struct {
	engine      *multiturn.UnifiedEngine
	name        string
	goal        string
	description string
}

// NewMischievousUser creates a MischievousProbe from registry config.
// Config keys mirror GOAT/Crescendo: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus multi-turn specific settings.
func NewMischievousUser(cfg registry.Config) (probes.Prober, error) {
	if cfg == nil {
		cfg = make(registry.Config)
	}

	// Create attacker generator
	attackerType := registry.GetString(cfg, "attacker_generator_type", "openai.OpenAI")
	attackerCfg := make(registry.Config)
	if ac, ok := cfg["attacker_config"].(map[string]any); ok {
		attackerCfg = ac
	}
	if model := registry.GetString(cfg, "attacker_model", ""); model != "" {
		attackerCfg["model"] = model
	}
	attacker, err := generators.Create(attackerType, attackerCfg)
	if err != nil {
		return nil, fmt.Errorf("creating attacker generator: %w", err)
	}

	// Create judge generator
	judgeType := registry.GetString(cfg, "judge_generator_type", "openai.OpenAI")
	judgeCfg := make(registry.Config)
	if jc, ok := cfg["judge_config"].(map[string]any); ok {
		judgeCfg = jc
	}
	if model := registry.GetString(cfg, "judge_model", ""); model != "" {
		judgeCfg["model"] = model
	}
	judge, err := generators.Create(judgeType, judgeCfg)
	if err != nil {
		return nil, fmt.Errorf("creating judge generator: %w", err)
	}

	defaults := multiturn.Defaults()
	defaults.MaxTurns = 5 // Mischievous user is subtler, fewer turns needed
	engineCfg := multiturn.ConfigFromMap(cfg, defaults)

	strategy := &mischievousstrat.Strategy{MaxTurns: engineCfg.MaxTurns}

	return &MischievousProbe{
		engine:      multiturn.NewUnifiedEngine(strategy, attacker, judge, engineCfg),
		name:        registry.GetString(cfg, "name", "mischievous.MischievousUser"),
		goal:        engineCfg.Goal,
		description: "Mischievous User: Subtle multi-turn attack simulating an innocent curious user (Tau-bench inspired)",
	}, nil
}

// Probe executes the mischievous user attack against the target generator.
func (p *MischievousProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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

func (p *MischievousProbe) Name() string               { return p.name }
func (p *MischievousProbe) Description() string        { return p.description }
func (p *MischievousProbe) Goal() string               { return p.goal }
func (p *MischievousProbe) GetPrimaryDetector() string { return "judge.Judge" }
func (p *MischievousProbe) GetPrompts() []string       { return []string{} }

// NewMischievousWithGenerators creates a MischievousProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewMischievousWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *MischievousProbe {
	strategy := &mischievousstrat.Strategy{MaxTurns: cfg.MaxTurns}
	return &MischievousProbe{
		engine:      multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
		name:        "mischievous.MischievousUser",
		goal:        cfg.Goal,
		description: "Mischievous User: Subtle multi-turn attack simulating an innocent curious user (Tau-bench inspired)",
	}
}

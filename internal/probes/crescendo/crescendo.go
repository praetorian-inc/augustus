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
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("crescendo.Crescendo", NewCrescendo)
}

// CrescendoProbe wraps the multi-turn engine with the Crescendo strategy.
type CrescendoProbe struct {
	engine      *multiturn.Engine
	name        string
	goal        string
	description string
}

// NewCrescendo creates a CrescendoProbe from registry config.
// Config keys mirror PAIR: attacker_generator_type, attacker_config,
// judge_generator_type, judge_config, plus multi-turn specific settings.
func NewCrescendo(cfg registry.Config) (probes.Prober, error) {
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

	engineCfg := multiturn.ConfigFromMap(cfg, multiturn.Defaults())

	return &CrescendoProbe{
		engine:      multiturn.New(&multiturn.CrescendoStrategy{}, attacker, judge, engineCfg),
		name:        registry.GetString(cfg, "name", "crescendo.Crescendo"),
		goal:        engineCfg.Goal,
		description: "Crescendo: Gradual escalation multi-turn attack (Russinovich et al., 2024)",
	}, nil
}

// Probe executes the Crescendo attack against the target generator.
func (p *CrescendoProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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

func (p *CrescendoProbe) Name() string               { return p.name }
func (p *CrescendoProbe) Description() string        { return p.description }
func (p *CrescendoProbe) Goal() string               { return p.goal }
func (p *CrescendoProbe) GetPrimaryDetector() string { return "judge.Judge" }
func (p *CrescendoProbe) GetPrompts() []string       { return []string{} }

// NewCrescendoWithGenerators creates a CrescendoProbe with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewCrescendoWithGenerators(attacker, judge probes.Generator, cfg multiturn.Config) *CrescendoProbe {
	return &CrescendoProbe{
		engine:      multiturn.New(&multiturn.CrescendoStrategy{}, attacker, judge, cfg),
		name:        "crescendo.Crescendo",
		goal:        cfg.Goal,
		description: "Crescendo: Gradual escalation multi-turn attack (Russinovich et al., 2024)",
	}
}

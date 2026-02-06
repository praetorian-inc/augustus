// Package tap provides TAP (Tree of Attacks with Pruning) probe for LLM testing.
//
// TAP implements tree-based attack generation that:
// 1. Generates adversarial prompts using a tree structure
// 2. Prunes ineffective branches based on scoring
// 3. Iteratively refines attacks based on model responses
//
// This package provides two types of probes:
// - Static YAML template probes (tap.TAPv1, tap.TAPv2) loaded via templates.go
// - IterativeTAP: the full TAP algorithm implementation using the shared attack engine
package tap

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("tap.IterativeTAP", NewIterativeTAP)
}

// IterativeTAP implements the full TAP algorithm using the shared attack engine.
// Unlike the YAML-template probes (which send static prompts), this probe
// uses an attacker LLM to generate a tree of adversarial prompts, pruning
// off-topic and low-scoring branches, scored by a judge LLM.
//
// Paper: https://arxiv.org/abs/2312.02119 (Mehrotra et al., 2023)
type IterativeTAP struct {
	engine      *attackengine.Engine
	name        string
	goal        string
	description string
}

// NewIterativeTAP creates an IterativeTAP probe from registry config.
func NewIterativeTAP(cfg registry.Config) (probes.Prober, error) {
	if cfg == nil {
		cfg = make(registry.Config)
	}

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

	engineCfg := attackengine.ConfigFromMap(cfg, attackengine.TAPDefaults())

	return &IterativeTAP{
		engine:      attackengine.New(attacker, judge, engineCfg),
		name:        registry.GetString(cfg, "name", "tap.IterativeTAP"),
		goal:        engineCfg.Goal,
		description: "TAP: Tree of Attacks with Pruning - tree-based jailbreak discovery with pruning",
	}, nil
}

// NewIterativeTAPWithGenerators creates an IterativeTAP with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewIterativeTAPWithGenerators(attacker, judge probes.Generator, cfg attackengine.Config) *IterativeTAP {
	return &IterativeTAP{
		engine:      attackengine.New(attacker, judge, cfg),
		name:        "tap.IterativeTAP",
		goal:        cfg.Goal,
		description: "TAP: Tree of Attacks with Pruning - tree-based jailbreak discovery with pruning",
	}
}

func (p *IterativeTAP) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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

func (p *IterativeTAP) Name() string              { return p.name }
func (p *IterativeTAP) Description() string        { return p.description }
func (p *IterativeTAP) Goal() string               { return p.goal }
func (p *IterativeTAP) GetPrimaryDetector() string { return "judge.Judge" }
func (p *IterativeTAP) GetPrompts() []string       { return []string{} }

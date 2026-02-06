// Package pair provides PAIR (Prompt Automatic Iterative Refinement) probe for LLM testing.
//
// PAIR implements an iterative prompt refinement attack that:
// 1. Starts with an initial adversarial prompt
// 2. Uses an attacker model to refine the prompt based on target model responses
// 3. Iteratively improves the attack until successful or max iterations reached
//
// This is based on the PAIR methodology for automated jailbreak discovery.
package pair

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Note: PAIR probes are now registered via YAML templates in templates.go
// The init() function that registered hardcoded probes has been removed.

// Note: Hardcoded PAIR probes (NewPAIR, NewPAIRBasic) have been removed.
// PAIR probes are now defined as YAML templates in data/*.yaml and loaded via templates.go.

func init() {
	probes.Register("pair.IterativePAIR", NewIterativePAIR)
}

// IterativePAIR implements the full PAIR algorithm using the shared attack engine.
// Unlike the YAML-template SimpleProbe (which sends static prompts), this probe
// uses an attacker LLM to iteratively refine jailbreak prompts based on target
// responses, scored by a judge LLM.
//
// Paper: https://arxiv.org/abs/2310.08419 (Chao et al., 2023)
type IterativePAIR struct {
	engine      *attackengine.Engine
	name        string
	goal        string
	description string
}

func NewIterativePAIR(cfg registry.Config) (probes.Prober, error) {
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

	engineCfg := attackengine.ConfigFromMap(cfg, attackengine.PAIRDefaults())

	return &IterativePAIR{
		engine:      attackengine.New(attacker, judge, engineCfg),
		name:        registry.GetString(cfg, "name", "pair.IterativePAIR"),
		goal:        engineCfg.Goal,
		description: "PAIR: Prompt Automatic Iterative Refinement - iterative jailbreak discovery",
	}, nil
}

func (p *IterativePAIR) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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

func (p *IterativePAIR) Name() string              { return p.name }
func (p *IterativePAIR) Description() string        { return p.description }
func (p *IterativePAIR) Goal() string               { return p.goal }
func (p *IterativePAIR) GetPrimaryDetector() string { return "judge.Judge" }
func (p *IterativePAIR) GetPrompts() []string       { return []string{} }

// NewIterativePAIRWithGenerators creates an IterativePAIR with pre-built generators.
// This is primarily for testing where mock generators need to be injected.
func NewIterativePAIRWithGenerators(attacker, judge probes.Generator, cfg attackengine.Config) *IterativePAIR {
	return &IterativePAIR{
		engine:      attackengine.New(attacker, judge, cfg),
		name:        "pair.IterativePAIR",
		goal:        cfg.Goal,
		description: "PAIR: Prompt Automatic Iterative Refinement - iterative jailbreak discovery",
	}
}

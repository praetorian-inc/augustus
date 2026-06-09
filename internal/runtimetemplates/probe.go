package runtimetemplates

import (
	"context"
	"maps"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// MultiTurnTemplateProbe runs a YAML-defined multi-turn strategy through the
// unified multi-turn attack engine. It mirrors multiturn.BaseMultiTurnProbe but
// reports the detector named in the template's info.detector field rather than
// the hardcoded default.
type MultiTurnTemplateProbe struct {
	engine   *multiturn.UnifiedEngine
	name     string
	goal     string
	desc     string
	detector string
}

// newMultiTurnProbeWithGenerators builds a probe from pre-constructed components.
// Used directly by tests and indirectly by the registry factory.
func newMultiTurnProbeWithGenerators(name, desc, detector string, strategy multiturn.Strategy, attacker, judge types.Generator, cfg multiturn.Config) *MultiTurnTemplateProbe {
	return &MultiTurnTemplateProbe{
		engine:   multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
		name:     name,
		goal:     cfg.Goal,
		desc:     desc,
		detector: detector,
	}
}

// Probe executes the multi-turn attack and stamps each attempt with this
// probe's name and configured detector.
func (p *MultiTurnTemplateProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	attempts, err := p.engine.Run(ctx, gen)
	if err != nil {
		return nil, err
	}
	for _, a := range attempts {
		a.Probe = p.name
		a.Detector = p.detector
	}
	return attempts, nil
}

func (p *MultiTurnTemplateProbe) Name() string               { return p.name }
func (p *MultiTurnTemplateProbe) Description() string        { return p.desc }
func (p *MultiTurnTemplateProbe) Goal() string               { return p.goal }
func (p *MultiTurnTemplateProbe) GetPrimaryDetector() string { return p.detector }
func (p *MultiTurnTemplateProbe) GetPrompts() []string       { return []string{} }

// buildEngineConfigMap merges a multi-turn template's engine block with optional
// scan-time config into the registry.Config that multiturn.CreateGenerators reads.
// All template engine parameters (generator types, max_turns, thresholds, goal)
// are defaults; any matching key in the scan-time config overrides them, so a
// template can be re-aimed (goal, model, generator types, turn budget) without
// editing the file. Goal defaults to info.goal when not set at scan time.
func buildEngineConfigMap(tmpl *templates.ProbeTemplate, cfg registry.Config) registry.Config {
	m := registry.Config{}

	if e := tmpl.Engine; e != nil {
		m["attacker_generator_type"] = e.AttackerGeneratorType
		m["judge_generator_type"] = e.JudgeGeneratorType
		if e.AttackerModel != "" {
			m["attacker_model"] = e.AttackerModel
		}
		if e.MaxTurns > 0 {
			m["max_turns"] = e.MaxTurns
		}
		if e.SuccessThreshold > 0 {
			m["success_threshold"] = e.SuccessThreshold
		}
		if e.MaxRefusalRetries > 0 {
			m["max_refusal_retries"] = e.MaxRefusalRetries
		}
		if e.MaxBacktracks > 0 {
			m["max_backtracks"] = e.MaxBacktracks
		}
		if e.Stateful {
			m["stateful"] = true
		}
	}

	// Goal default from the template; scan-time config overrides below.
	if tmpl.Info.Goal != "" {
		m["goal"] = tmpl.Info.Goal
	}

	maps.Copy(m, cfg)
	return m
}

// newMultiTurnProbe builds a MultiTurnTemplateProbe from a template and the
// scan-time config, constructing the attacker/judge generators and strategy.
func newMultiTurnProbe(tmpl *templates.ProbeTemplate, cfg registry.Config) (types.Prober, error) {
	engineMap := buildEngineConfigMap(tmpl, cfg)

	attacker, judge, engineCfg, err := multiturn.CreateGenerators(engineMap, nil)
	if err != nil {
		return nil, err
	}

	strategy, err := newTemplateStrategy(tmpl.ID, tmpl.Strategy, engineCfg.MaxTurns)
	if err != nil {
		return nil, err
	}

	return newMultiTurnProbeWithGenerators(
		tmpl.ID, tmpl.Info.Description, tmpl.Info.Detector,
		strategy, attacker, judge, engineCfg,
	), nil
}

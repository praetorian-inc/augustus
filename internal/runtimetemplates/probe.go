package runtimetemplates

import (
	"maps"
	"strings"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// MultiTurnTemplateProbe runs a YAML-defined multi-turn strategy through the
// unified multi-turn attack engine. It embeds BaseMultiTurnProbe (which handles
// the run loop, naming, and detector reporting via its Detector field) and adds
// per-template detector config.
type MultiTurnTemplateProbe struct {
	multiturn.BaseMultiTurnProbe
	detectorConfig     map[string]any
	secondaryDetectors []types.SecondaryDetector
}

// GetDetectorConfig returns per-template detector configuration overrides
// (info.detector_config). Implements types.ProbeDetectorConfig so multi-turn
// templates are as self-contained as static ones. Returns nil when unset.
func (p *MultiTurnTemplateProbe) GetDetectorConfig() map[string]any {
	return p.detectorConfig
}

// GetSecondaryDetectors returns additional detectors to run alongside the
// primary (info.secondary_detectors). Implements types.ProbeSecondaryDetectors
// so multi-turn templates honor secondary detectors like static ones do.
func (p *MultiTurnTemplateProbe) GetSecondaryDetectors() []types.SecondaryDetector {
	return p.secondaryDetectors
}

// newMultiTurnProbeWithGenerators builds a probe from pre-constructed components.
// Used directly by tests and indirectly by the registry factory.
func newMultiTurnProbeWithGenerators(name, desc, detector string, detectorConfig map[string]any, strategy multiturn.Strategy, attacker, judge types.Generator, cfg multiturn.Config) *MultiTurnTemplateProbe {
	return &MultiTurnTemplateProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine:    multiturn.NewUnifiedEngine(strategy, attacker, judge, cfg),
			ProbeName: name,
			ProbeGoal: cfg.Goal,
			ProbeDesc: desc,
			Detector:  detector,
		},
		detectorConfig: detectorConfig,
	}
}

// buildEngineConfigMap merges a multi-turn template's engine block with optional
// scan-time config into the registry.Config that multiturn.CreateGenerators reads.
// All template engine parameters (generator types, max_turns, thresholds, goal)
// are defaults; any matching key in the scan-time config overrides them, so a
// template can be re-aimed (goal, model, generator types, turn budget) without
// editing the file. Goal defaults to info.goal when not set at scan time.
//
// The string keys below MUST match the keys multiturn.ConfigFromMap /
// CreateGenerators read. This stringly-typed coupling is the price of reusing the
// engine's existing map-based config contract; it is pinned by
// TestBuildEngineConfigMap_RoundTripsThroughEngineConfig so a key rename in
// multiturn fails this package's tests rather than silently dropping config.
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

	probe := newMultiTurnProbeWithGenerators(
		tmpl.ID, tmpl.Info.Description, tmpl.Info.Detector, tmpl.Info.DetectorConfig,
		strategy, attacker, judge, engineCfg,
	)
	probe.secondaryDetectors = secondaryDetectorsFromTemplate(tmpl)
	return probe, nil
}

// secondaryDetectorsFromTemplate converts a template's info.secondary_detectors
// into the runtime type. Returns nil when none are declared.
func secondaryDetectorsFromTemplate(tmpl *templates.ProbeTemplate) []types.SecondaryDetector {
	if len(tmpl.Info.SecondaryDetectors) == 0 {
		return nil
	}
	out := make([]types.SecondaryDetector, len(tmpl.Info.SecondaryDetectors))
	for i, s := range tmpl.Info.SecondaryDetectors {
		// Trim the name so it matches validateSecondaryDetectors()'s trimmed
		// checks and resolves cleanly in the detector registry.
		out[i] = types.SecondaryDetector{Name: strings.TrimSpace(s.Name), Config: s.Config}
	}
	return out
}

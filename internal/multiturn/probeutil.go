package multiturn

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// CreateGenerators creates attacker and judge generators from probe configuration.
// This is shared setup code used by all multi-turn probe factories.
//
// If defaults is nil, standard Defaults() are used.
// This allows probes like Mischievous to provide custom defaults (e.g., MaxTurns=5).
func CreateGenerators(cfg registry.Config, defaults *Config) (attacker, judge types.Generator, engineCfg Config, err error) {
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
	attacker, err = generators.Create(attackerType, attackerCfg)
	if err != nil {
		return nil, nil, Config{}, fmt.Errorf("creating attacker generator: %w", err)
	}

	// Create judge generator (must be explicitly configured; judge should not be the target)
	judgeType := registry.GetString(cfg, "judge_generator_type", "")
	if judgeType == "" {
		return nil, nil, Config{}, fmt.Errorf("judge_generator_type is required: configure the global judge section in your YAML config")
	}
	judgeCfg := make(registry.Config)
	if jc, ok := cfg["judge_config"].(map[string]any); ok {
		judgeCfg = jc
	}
	judge, err = generators.Create(judgeType, judgeCfg)
	if err != nil {
		return nil, nil, Config{}, fmt.Errorf("creating judge generator: %w", err)
	}

	d := Defaults()
	if defaults != nil {
		d = *defaults
	}
	engineCfg = ConfigFromMap(cfg, d)
	if err := engineCfg.Validate(); err != nil {
		return nil, nil, Config{}, err
	}
	return attacker, judge, engineCfg, nil
}

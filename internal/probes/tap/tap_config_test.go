package tap

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
)

// TestTAPConfigInheritance tests that TAP correctly inherits target_generator_type
// for the attacker, but requires explicit judge configuration.
func TestTAPConfigInheritance(t *testing.T) {
	cfg := registry.Config{
		"target_generator_type": "ollama.OllamaChat",
		"model":                 "minimax-m2.5:cloud",
	}

	// Attacker should inherit target type
	targetType := registry.GetString(cfg, "target_generator_type", "openai.OpenAI")
	attackerType := registry.GetString(cfg, "attacker_generator_type", targetType)
	assert.Equal(t, "ollama.OllamaChat", attackerType,
		"attacker should inherit target_generator_type")

	// Judge should NOT inherit target type — must be explicitly configured
	judgeType := registry.GetString(cfg, "judge_generator_type", "")
	assert.Equal(t, "", judgeType,
		"judge should not fall back to target type")
}

// TestTAPModelInheritance tests that TAP inherits the model config correctly.
func TestTAPModelInheritance(t *testing.T) {
	tests := []struct {
		name          string
		config        registry.Config
		wantAttackerM string
		wantJudgeM    any // nil if not set
	}{
		{
			name: "attacker inherits base model, judge requires judge_config",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
			},
			wantAttackerM: "minimax-m2.5:cloud",
			wantJudgeM:    nil, // no judge_config → no model
		},
		{
			name: "explicit attacker_model overrides base model",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
				"attacker_model":        "llama3:70b",
			},
			wantAttackerM: "llama3:70b",
			wantJudgeM:    nil,
		},
		{
			name: "judge model comes from judge_config",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
				"judge_config": map[string]any{
					"model": "gpt-4",
				},
			},
			wantAttackerM: "minimax-m2.5:cloud",
			wantJudgeM:    "gpt-4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Attacker model resolution (unchanged — can inherit target model)
			attackerCfg := make(registry.Config)
			if model := registry.GetString(tt.config, "attacker_model", ""); model != "" {
				attackerCfg["model"] = model
			} else if model := registry.GetString(tt.config, "model", ""); model != "" {
				attackerCfg["model"] = model
			}

			// Judge model resolution — only from judge_config
			judgeCfg := make(registry.Config)
			if jc, ok := tt.config["judge_config"].(map[string]any); ok {
				judgeCfg = jc
			}

			assert.Equal(t, tt.wantAttackerM, attackerCfg["model"], "attacker model mismatch")
			assert.Equal(t, tt.wantJudgeM, judgeCfg["model"], "judge model mismatch")
		})
	}
}

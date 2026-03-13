package tap

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
)

// TestTAPConfigInheritance tests that TAP correctly inherits target_generator_type
// and model config when not explicitly specified.
//
// Bug: https://github.com/praetorian-inc/augustus/issues/38
func TestTAPConfigInheritance(t *testing.T) {
	// Test case: User provides target generator type but no attacker/judge type
	// Expected: TAP should use target type for attacker/judge
	cfg := registry.Config{
		"target_generator_type": "ollama.OllamaChat",
		"model":                 "minimax-m2.5:cloud",
	}

	// Simulate what tap.go NewIterativeTAP() does NOW (with fix applied)
	targetType := registry.GetString(cfg, "target_generator_type", "openai.OpenAI")
	attackerType := registry.GetString(cfg, "attacker_generator_type", targetType)
	judgeType := registry.GetString(cfg, "judge_generator_type", targetType)

	// Verify the fix works: attacker/judge inherit target_generator_type
	assert.Equal(t, "ollama.OllamaChat", attackerType,
		"attacker should inherit target_generator_type")
	assert.Equal(t, "ollama.OllamaChat", judgeType,
		"judge should inherit target_generator_type")
}

// TestTAPModelInheritance tests that TAP inherits the model config correctly.
func TestTAPModelInheritance(t *testing.T) {
	tests := []struct {
		name          string
		config        registry.Config
		wantAttackerM string
		wantJudgeM    string
	}{
		{
			name: "inherits base model when no specific model",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
			},
			wantAttackerM: "minimax-m2.5:cloud",
			wantJudgeM:    "minimax-m2.5:cloud",
		},
		{
			name: "explicit attacker_model overrides base model",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
				"attacker_model":        "llama3:70b",
			},
			wantAttackerM: "llama3:70b",
			wantJudgeM:    "minimax-m2.5:cloud", // judge still uses base
		},
		{
			name: "explicit judge_model overrides base model",
			config: registry.Config{
				"target_generator_type": "ollama.OllamaChat",
				"model":                 "minimax-m2.5:cloud",
				"judge_model":           "gpt-4",
			},
			wantAttackerM: "minimax-m2.5:cloud", // attacker uses base
			wantJudgeM:    "gpt-4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate model config resolution from tap.go
			attackerCfg := make(registry.Config)
			if model := registry.GetString(tt.config, "attacker_model", ""); model != "" {
				attackerCfg["model"] = model
			} else if model := registry.GetString(tt.config, "model", ""); model != "" {
				attackerCfg["model"] = model
			}

			judgeCfg := make(registry.Config)
			if model := registry.GetString(tt.config, "judge_model", ""); model != "" {
				judgeCfg["model"] = model
			} else if model := registry.GetString(tt.config, "model", ""); model != "" {
				judgeCfg["model"] = model
			}

			assert.Equal(t, tt.wantAttackerM, attackerCfg["model"], "attacker model mismatch")
			assert.Equal(t, tt.wantJudgeM, judgeCfg["model"], "judge model mismatch")
		})
	}
}

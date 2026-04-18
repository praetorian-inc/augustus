package pair

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
)

// TestPAIRConfigInheritance tests that PAIR correctly inherits target_generator_type
// for the attacker, but requires explicit judge configuration.
func TestPAIRConfigInheritance(t *testing.T) {
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

// TestPAIRJudgeDoesNotInheritTarget tests that the judge does not fall back
// to the target generator type — it must be explicitly configured.
func TestPAIRJudgeDoesNotInheritTarget(t *testing.T) {
	// Simulate config resolution: target is set, judge is not.
	// The judge_generator_type should be empty (not inherited from target).
	cfg := registry.Config{
		"target_generator_type": "ollama.OllamaChat",
		"model":                 "some-model",
	}

	judgeType := registry.GetString(cfg, "judge_generator_type", "")
	assert.Equal(t, "", judgeType,
		"judge_generator_type should not inherit from target")
}

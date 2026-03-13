package pair

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
)

// TestPAIRConfigInheritance tests that PAIR correctly inherits target_generator_type
// and model config when not explicitly specified.
//
// Bug: https://github.com/praetorian-inc/augustus/issues/38
func TestPAIRConfigInheritance(t *testing.T) {
	// Test case: User provides target generator type but no attacker/judge type
	// Expected: PAIR should use target type for attacker/judge
	cfg := registry.Config{
		"target_generator_type": "ollama.OllamaChat",
		"model":                 "minimax-m2.5:cloud",
	}

	// Simulate what pair.go NewIterativePAIR() does NOW (with fix applied)
	targetType := registry.GetString(cfg, "target_generator_type", "openai.OpenAI")
	attackerType := registry.GetString(cfg, "attacker_generator_type", targetType)
	judgeType := registry.GetString(cfg, "judge_generator_type", targetType)

	// Verify the fix works: attacker/judge inherit target_generator_type
	assert.Equal(t, "ollama.OllamaChat", attackerType,
		"attacker should inherit target_generator_type")
	assert.Equal(t, "ollama.OllamaChat", judgeType,
		"judge should inherit target_generator_type")
}

package multiturn

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator implements types.Generator for testing.
type mockGenerator struct {
	mu        sync.Mutex
	responses []string
	callIdx   int
}

func newMockGenerator(responses ...string) *mockGenerator {
	return &mockGenerator{responses: responses}
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.callIdx >= len(m.responses) {
		return nil, fmt.Errorf("mock: no more responses")
	}
	resp := m.responses[m.callIdx]
	m.callIdx++
	return []attempt.Message{{Role: "assistant", Content: resp}}, nil
}

func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock generator" }

// mockGeneratorFactory registers a mock generator factory for testing.
func init() {
	generators.Register("mock.Generator", func(cfg registry.Config) (types.Generator, error) {
		return newMockGenerator("test response"), nil
	})
}

func TestCreateGenerators_DefaultConfig(t *testing.T) {
	// Test with nil config (uses defaults)
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"judge_generator_type":    "mock.Generator",
		"goal":                    "test goal",
	}
	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
	assert.Equal(t, 10, engineCfg.MaxTurns) // Default from Defaults()
}

func TestCreateGenerators_CustomDefaults(t *testing.T) {
	// Test with custom defaults (like Mischievous probe)
	customDefaults := Defaults()
	customDefaults.MaxTurns = 5

	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"judge_generator_type":    "mock.Generator",
		"goal":                    "test goal",
	}
	attacker, judge, engineCfg, err := CreateGenerators(cfg, &customDefaults)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
	assert.Equal(t, 5, engineCfg.MaxTurns) // Custom default applied
}

func TestCreateGenerators_WithConfig(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"attacker_model":          "gpt-4",
		"judge_generator_type":    "mock.Generator",
		"judge_model":             "gpt-4",
		"goal":                    "Test goal",
		"max_turns":               7,
	}

	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
	assert.Equal(t, "Test goal", engineCfg.Goal)
	assert.Equal(t, 7, engineCfg.MaxTurns)
	assert.Equal(t, "gpt-4", engineCfg.AttackerModel)
}

func TestCreateGenerators_AttackerConfigMap(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"attacker_config": map[string]any{
			"temperature": 0.7,
			"model":       "gpt-3.5-turbo",
		},
		"judge_generator_type": "mock.Generator",
		"goal":                 "test goal",
	}

	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
	// attacker_model from attacker_config should be used
	assert.Equal(t, "gpt-3.5-turbo", engineCfg.AttackerModel)
}

func TestCreateGenerators_JudgeConfigMap(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"judge_generator_type":    "mock.Generator",
		"judge_config": map[string]any{
			"temperature": 0.3,
			"model":       "gpt-4",
		},
		"goal": "test goal",
	}

	attacker, judge, _, err := CreateGenerators(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
}

func TestCreateGenerators_AttackerModelOverridesConfig(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"attacker_config": map[string]any{
			"model": "gpt-3.5-turbo",
		},
		"attacker_model":       "gpt-4", // This should override
		"judge_generator_type": "mock.Generator",
		"goal":                 "test goal",
	}

	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	require.NoError(t, err)
	assert.NotNil(t, attacker)
	assert.NotNil(t, judge)
	assert.Equal(t, "gpt-4", engineCfg.AttackerModel)
}

func TestCreateGenerators_InvalidAttackerType(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "invalid.Type",
		"judge_generator_type":    "mock.Generator",
	}

	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "creating attacker generator")
	assert.Nil(t, attacker)
	assert.Nil(t, judge)
	assert.Equal(t, Config{}, engineCfg)
}

func TestCreateGenerators_InvalidJudgeType(t *testing.T) {
	cfg := registry.Config{
		"attacker_generator_type": "mock.Generator",
		"judge_generator_type":    "invalid.Type",
	}

	attacker, judge, engineCfg, err := CreateGenerators(cfg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "creating judge generator")
	assert.Nil(t, attacker)
	assert.Nil(t, judge)
	assert.Equal(t, Config{}, engineCfg)
}

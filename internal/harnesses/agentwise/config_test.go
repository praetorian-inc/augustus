package agentwise

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentConfigFromMap(t *testing.T) {
	m := registry.Config{
		"has_tools":       true,
		"has_browsing":    false,
		"has_memory":      true,
		"has_multi_agent": true,
		"tool_list":       []string{"calculator", "search"},
	}

	cfg, err := AgentConfigFromMap(m)
	require.NoError(t, err)

	assert.True(t, cfg.HasTools)
	assert.False(t, cfg.HasBrowsing)
	assert.True(t, cfg.HasMemory)
	assert.True(t, cfg.HasMultiAgent)
	assert.Equal(t, []string{"calculator", "search"}, cfg.ToolList)
}

func TestAgentConfigDefaults(t *testing.T) {
	cfg := DefaultAgentConfig()

	assert.False(t, cfg.HasTools)
	assert.False(t, cfg.HasBrowsing)
	assert.False(t, cfg.HasMemory)
	assert.False(t, cfg.HasMultiAgent)
	assert.Nil(t, cfg.ToolList)
}

func TestAgentConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyAgentOptions(
		DefaultAgentConfig(),
		WithTools(true),
		WithBrowsing(true),
		WithToolList([]string{"web_search"}),
	)

	assert.True(t, cfg.HasTools)
	assert.True(t, cfg.HasBrowsing)
	assert.Equal(t, []string{"web_search"}, cfg.ToolList)
}

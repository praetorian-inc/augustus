package agentwise

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// DefaultAgentConfig returns an AgentConfig with default values (all false).
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		HasTools:      false,
		HasBrowsing:   false,
		HasMemory:     false,
		HasMultiAgent: false,
		ToolList:      nil,
	}
}

// AgentConfigFromMap parses a registry.Config map into an AgentConfig.
// This enables backward compatibility with YAML/JSON configuration.
func AgentConfigFromMap(m registry.Config) (AgentConfig, error) {
	cfg := DefaultAgentConfig()

	// Optional: boolean capabilities
	cfg.HasTools = registry.GetBool(m, "has_tools", cfg.HasTools)
	cfg.HasBrowsing = registry.GetBool(m, "has_browsing", cfg.HasBrowsing)
	cfg.HasMemory = registry.GetBool(m, "has_memory", cfg.HasMemory)
	cfg.HasMultiAgent = registry.GetBool(m, "has_multi_agent", cfg.HasMultiAgent)

	// Optional: tool list
	cfg.ToolList = registry.GetStringSlice(m, "tool_list", cfg.ToolList)

	return cfg, nil
}

// AgentOption is a functional option for AgentConfig.
type AgentOption = registry.Option[AgentConfig]

// ApplyAgentOptions applies functional options to an AgentConfig.
func ApplyAgentOptions(cfg AgentConfig, opts ...AgentOption) AgentConfig {
	return registry.ApplyOptions(cfg, opts...)
}

// WithTools sets the HasTools capability.
func WithTools(hasTools bool) AgentOption {
	return func(c *AgentConfig) {
		c.HasTools = hasTools
	}
}

// WithBrowsing sets the HasBrowsing capability.
func WithBrowsing(hasBrowsing bool) AgentOption {
	return func(c *AgentConfig) {
		c.HasBrowsing = hasBrowsing
	}
}

// WithMemory sets the HasMemory capability.
func WithMemory(hasMemory bool) AgentOption {
	return func(c *AgentConfig) {
		c.HasMemory = hasMemory
	}
}

// WithMultiAgent sets the HasMultiAgent capability.
func WithMultiAgent(hasMultiAgent bool) AgentOption {
	return func(c *AgentConfig) {
		c.HasMultiAgent = hasMultiAgent
	}
}

// WithToolList sets the tool list.
func WithToolList(tools []string) AgentOption {
	return func(c *AgentConfig) {
		c.ToolList = tools
	}
}

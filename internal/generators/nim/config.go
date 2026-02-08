// Package nim provides NIM (NVIDIA Inference Microservices) generators for Augustus.
package nim

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// Config holds configuration for NIM generator variants.
// It embeds BaseConfig for common fields and adds NIM-specific client.
type Config struct {
	openaicompat.BaseConfig
	// NIM-specific: OpenAI client configured for NIM endpoint
	Client *goopenai.Client
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BaseConfig: openaicompat.DefaultBaseConfig(),
	}
}

// ConfigFromMap creates a Config from a registry.Config map.
// The defaultTemp parameter sets the default temperature when none is provided.
func ConfigFromMap(m registry.Config, defaultTemp float32) (Config, error) {
	// Parse common fields using BaseConfig
	baseConfig, err := openaicompat.BaseConfigFromMap(m, "NIM_API_KEY", "nim")
	if err != nil {
		return Config{}, err
	}

	// Override default temperature if specified
	if defaultTemp != 0 && baseConfig.Temperature == openaicompat.DefaultBaseConfig().Temperature {
		baseConfig.Temperature = defaultTemp
	}

	// Set default base URL if not provided
	if baseConfig.BaseURL == "" {
		baseConfig.BaseURL = DefaultBaseURL
	}

	// Create OpenAI client configured for NIM endpoint
	clientConfig := goopenai.DefaultConfig(baseConfig.APIKey)
	clientConfig.BaseURL = baseConfig.BaseURL
	client := goopenai.NewClientWithConfig(clientConfig)

	return Config{
		BaseConfig: baseConfig,
		Client:     client,
	}, nil
}

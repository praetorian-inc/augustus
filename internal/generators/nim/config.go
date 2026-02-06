package nim

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// nimConfig holds the shared configuration for all NIM generator variants
// (NVOpenAICompletion, NVMultimodal, Vision). Each variant embeds this struct
// to avoid duplicating the constructor and field definitions.
type nimConfig struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
}

// newNIMConfig parses registry config into a nimConfig with an initialized OpenAI client.
// The generatorName is used for error messages (e.g., "nim.NVOpenAICompletion").
// The defaultTemp sets the default temperature when none is provided in config.
func newNIMConfig(cfg registry.Config, generatorName string, defaultTemp float32) (*nimConfig, error) {
	nc := &nimConfig{
		temperature: defaultTemp,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("%s requires 'model' configuration", generatorName)
	}
	nc.model = model

	// API key: from config or env var
	apiKey, err := getAPIKey(cfg)
	if err != nil {
		return nil, err
	}

	// Create client config
	config := goopenai.DefaultConfig(apiKey)

	// Base URL: from config or use default NIM endpoint
	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		config.BaseURL = baseURL
	} else {
		config.BaseURL = DefaultBaseURL
	}

	nc.client = goopenai.NewClientWithConfig(config)

	// Optional: temperature
	if temp, ok := cfg["temperature"].(float64); ok {
		nc.temperature = float32(temp)
	}

	// Optional: max_tokens
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		nc.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		nc.maxTokens = int(maxTokens)
	}

	// Optional: top_p
	if topP, ok := cfg["top_p"].(float64); ok {
		nc.topP = float32(topP)
	}

	return nc, nil
}

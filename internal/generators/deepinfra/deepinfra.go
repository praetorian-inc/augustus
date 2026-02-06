// Package deepinfra provides a DeepInfra generator for Augustus.
//
// DeepInfra uses an OpenAI-compatible chat completions API format and supports
// llama and falcon models.
package deepinfra

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("deepinfra.DeepInfra", NewDeepInfra)
}

// NewDeepInfra creates a new DeepInfra generator from configuration.
func NewDeepInfra(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "deepinfra.DeepInfra",
		Description:    "DeepInfra inference API generator for llama and falcon models",
		Provider:       "deepinfra",
		DefaultBaseURL: "https://api.deepinfra.com/v1/openai",
		EnvVar:         "DEEPINFRA_API_KEY",
	})
}

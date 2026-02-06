// Package fireworks provides a Fireworks AI generator for Augustus.
//
// Fireworks uses an OpenAI-compatible chat completions API format.
package fireworks

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("fireworks.Fireworks", NewFireworks)
}

// NewFireworks creates a new Fireworks generator from configuration.
func NewFireworks(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "fireworks.Fireworks",
		Description:    "Fireworks AI fast inference API generator for various open-source models",
		Provider:       "fireworks",
		DefaultBaseURL: "https://api.fireworks.ai/inference/v1",
		EnvVar:         "FIREWORKS_API_KEY",
	})
}

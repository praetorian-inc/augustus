// Package together provides a Together.ai generator for Augustus.
//
// Together.ai uses an OpenAI-compatible chat completions API format.
package together

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("together.Together", NewTogether)
}

// NewTogether creates a new Together.ai generator from configuration.
func NewTogether(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "together.Together",
		Description:    "Together.ai API generator for open-source models",
		Provider:       "together",
		DefaultBaseURL: "https://api.together.xyz/v1",
		EnvVar:         "TOGETHER_API_KEY",
	})
}

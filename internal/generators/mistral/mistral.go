// Package mistral provides a Mistral AI generator for Augustus.
//
// This package implements the Generator interface for Mistral's API.
// It supports Mistral models including Mistral-7B, Mistral-8x7B, etc.
package mistral

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("mistral.Mistral", NewMistral)
}

// NewMistral creates a Mistral generator using CompatGenerator.
func NewMistral(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "mistral.Mistral",
		Description:    "Mistral AI chat completion generator",
		Provider:       "mistral",
		DefaultBaseURL: "https://api.mistral.ai/v1",
		EnvVar:         "MISTRAL_API_KEY",
	})
}

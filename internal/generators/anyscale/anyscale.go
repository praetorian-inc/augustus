// Package anyscale provides an Anyscale generator for Augustus.
//
// This package implements the Generator interface for Anyscale's OpenAI-compatible API.
// Anyscale provides access to llama-2 and mistral models through an OpenAI-compatible interface.
package anyscale

import (
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("anyscale.Anyscale", NewAnyscale)
}

// NewAnyscale creates an Anyscale generator using CompatGenerator with retry support.
func NewAnyscale(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "anyscale.Anyscale",
		Description:    "Anyscale Endpoints API generator supporting Llama-2, Mistral, and other open-source models",
		Provider:       "anyscale",
		DefaultBaseURL: "https://api.anyscale.com/v1",
		EnvVar:         "ANYSCALE_API_KEY",
		RetryConfig: &openaicompat.RetryConfig{
			MaxRetries:  3,
			InitialWait: 1 * time.Second,
			MaxWait:     30 * time.Second,
		},
	})
}

// Package groq provides a Groq generator for Augustus.
//
// This package implements the Generator interface for Groq's fast inference API.
// Groq uses an OpenAI-compatible chat completions API format.
package groq

import (
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("groq.Groq", NewGroq)
}

// NewGroq creates a Groq generator using CompatGenerator with retry support.
func NewGroq(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "groq.Groq",
		Description:    "Groq fast inference API generator",
		Provider:       "groq",
		DefaultBaseURL: "https://api.groq.com/openai/v1",
		EnvVar:         "GROQ_API_KEY",
		RetryConfig: &openaicompat.RetryConfig{
			MaxRetries:  3,
			InitialWait: 1 * time.Second,
			MaxWait:     30 * time.Second,
		},
	})
}

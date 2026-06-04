// Package xai provides an xAI Grok generator for Augustus.
//
// xAI exposes an OpenAI-compatible Chat Completions API at api.x.ai/v1,
// so this generator is a thin wrapper around openaicompat.NewGenerator
// pointed at the xAI endpoint with xAI authentication. All multimodal
// content carried by Message.Images flows through openaicompat's existing
// image_url content-part path — no Grok-specific wire format required.
//
// Auth: XAI_API_KEY environment variable, or "api_key" / "xai_api_key" in
// the registry.Config map.
//
// Model identifiers: pass any current Grok model in the "model" field
// (e.g. grok-4-vision, grok-4, grok-3-vision, grok-2-vision-1212).
package xai

import (
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("xai.XAI", NewXAI)
}

// NewXAI creates an xAI Grok generator via the OpenAI-compatible helper.
func NewXAI(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "xai.XAI",
		Description:    "xAI Grok generator (OpenAI-compatible API, multimodal text + image)",
		Provider:       "xai",
		DefaultBaseURL: "https://api.x.ai/v1",
		EnvVar:         "XAI_API_KEY",
		RetryConfig: &openaicompat.RetryConfig{
			MaxRetries:  3,
			InitialWait: 1 * time.Second,
			MaxWait:     30 * time.Second,
		},
	})
}

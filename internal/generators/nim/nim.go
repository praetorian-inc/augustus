// Package nim provides a NVIDIA NIM generator for Augustus.
//
// NIM (NVIDIA Inference Microservices) provides OpenAI-compatible
// APIs for models like LLaMA-2 and Mixtral.
package nim

import (

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// DefaultBaseURL is the default NIM API base URL.
	DefaultBaseURL = "https://integrate.api.nvidia.com/v1"
)

func init() {
	generators.Register("nim.NIM", NewNIM)
	generators.Register("nim.NVOpenAICompletion", NewNVOpenAICompletion)
	generators.Register("nim.NVMultimodal", NewNVMultimodal)
	generators.Register("nim.Vision", NewVision)
}

// NewNIM creates a new NIM generator from configuration.
func NewNIM(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:           "nim.NIM",
		Description:    "NVIDIA NIM (Inference Microservices) generator for LLaMA-2, Mixtral, and other models",
		Provider:       "nim",
		DefaultBaseURL: DefaultBaseURL,
		EnvVar:         "NIM_API_KEY",
	})
}


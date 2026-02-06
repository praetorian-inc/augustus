// Package nemo provides a NVIDIA NeMo generator for Augustus.
//
// NeMo provides OpenAI-compatible APIs for models hosted on NVIDIA NGC.
package nemo

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("nemo.NeMo", NewNeMo)
}

// NewNeMo creates a new NeMo generator from configuration.
func NewNeMo(cfg registry.Config) (generators.Generator, error) {
	return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
		Name:               "nemo.NeMo",
		Description:        "NVIDIA NeMo generator for models hosted on NGC",
		Provider:           "nemo",
		DefaultBaseURL:     "https://api.llm.ngc.nvidia.com/v1",
		EnvVar:             "NGC_API_KEY",
		DefaultTemperature: 0.9,
	})
}

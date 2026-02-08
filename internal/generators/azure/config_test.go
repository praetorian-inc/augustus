package azure

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureConfig_ModelEnvFallback(t *testing.T) {
	t.Setenv("AZURE_MODEL_NAME", "gpt-4-azure")

	cfg, err := ConfigFromMap(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "gpt-4-azure", cfg.Model)
}

func TestAzureConfig_ModelFromConfig(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"model": "gpt-4-turbo"})
	require.NoError(t, err)
	assert.Equal(t, "gpt-4-turbo", cfg.Model)
}

func TestAzureConfig_EndpointEnvFallback(t *testing.T) {
	t.Setenv("AZURE_ENDPOINT", "https://my-resource.openai.azure.com")

	cfg, err := ConfigFromMap(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "https://my-resource.openai.azure.com", cfg.Endpoint)
}

func TestAzureConfig_DefaultAPIVersion(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "2024-06-01", cfg.APIVersion)
}

package vertex

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVertexConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, float64(0.7), cfg.Temperature)
	assert.Equal(t, 150, cfg.MaxOutputTokens)
	assert.Equal(t, "us-central1", cfg.Location)
	assert.Empty(t, cfg.Model)     // Must be set
	assert.Empty(t, cfg.ProjectID) // Must be set
	assert.Empty(t, cfg.APIKey)    // Optional (can use ADC)
}

func TestVertexConfigFromMap(t *testing.T) {
	m := registry.Config{
		"model":             "gemini-pro",
		"project_id":        "my-project-123",
		"location":          "europe-west1",
		"api_key":           "test-api-key",
		"temperature":       0.5,
		"max_output_tokens": 300,
		"top_p":             0.9,
		"top_k":             50,
		"stop_sequences":    []string{"END", "STOP"},
		"base_url":          "https://custom.vertex.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "gemini-pro", cfg.Model)
	assert.Equal(t, "my-project-123", cfg.ProjectID)
	assert.Equal(t, "europe-west1", cfg.Location)
	assert.Equal(t, "test-api-key", cfg.APIKey)
	assert.Equal(t, float64(0.5), cfg.Temperature)
	assert.Equal(t, 300, cfg.MaxOutputTokens)
	assert.Equal(t, float64(0.9), cfg.TopP)
	assert.Equal(t, 50, cfg.TopK)
	assert.Equal(t, []string{"END", "STOP"}, cfg.StopSequences)
	assert.Equal(t, "https://custom.vertex.com", cfg.BaseURL)
}

func TestVertexConfigFromMapMissingModel(t *testing.T) {
	m := registry.Config{"project_id": "my-project-123"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestVertexConfigFromMapMissingProjectID(t *testing.T) {
	m := registry.Config{"model": "gemini-pro"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project_id")
}

func TestVertexConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	os.Setenv("GOOGLE_API_KEY", "env-api-key")
	defer os.Unsetenv("GOOGLE_API_KEY")

	m := registry.Config{
		"model":      "gemini-pro",
		"project_id": "my-project-123",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "env-api-key", cfg.APIKey)
}

func TestVertexConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("gemini-pro"),
		WithProjectID("my-project-123"),
		WithLocation("asia-east1"),
		WithAPIKey("test-key"),
		WithTemperature(0.3),
		WithMaxOutputTokens(500),
		WithTopP(0.95),
		WithTopK(100),
		WithStopSequences([]string{"DONE"}),
		WithBaseURL("https://custom.com"),
	)

	assert.Equal(t, "gemini-pro", cfg.Model)
	assert.Equal(t, "my-project-123", cfg.ProjectID)
	assert.Equal(t, "asia-east1", cfg.Location)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float64(0.3), cfg.Temperature)
	assert.Equal(t, 500, cfg.MaxOutputTokens)
	assert.Equal(t, float64(0.95), cfg.TopP)
	assert.Equal(t, 100, cfg.TopK)
	assert.Equal(t, []string{"DONE"}, cfg.StopSequences)
	assert.Equal(t, "https://custom.com", cfg.BaseURL)
}

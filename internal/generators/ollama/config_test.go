package ollama

import (
	"os"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOllamaConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "http://127.0.0.1:11434", cfg.Host)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.Empty(t, cfg.Model) // Must be set
	assert.Nil(t, cfg.Temperature)
	assert.Nil(t, cfg.TopP)
	assert.Nil(t, cfg.TopK)
	assert.Nil(t, cfg.NumPredict)
}

func TestOllamaConfigFromMap(t *testing.T) {
	temp := float64(0.7)
	topP := float64(0.9)
	topK := 50
	numPredict := 100

	m := registry.Config{
		"model":       "llama2:7b",
		"host":        "http://localhost:11434",
		"timeout":     60,
		"temperature": temp,
		"top_p":       topP,
		"top_k":       topK,
		"num_predict": numPredict,
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "llama2:7b", cfg.Model)
	assert.Equal(t, "http://localhost:11434", cfg.Host)
	assert.Equal(t, 60*time.Second, cfg.Timeout)
	assert.NotNil(t, cfg.Temperature)
	assert.Equal(t, temp, *cfg.Temperature)
	assert.NotNil(t, cfg.TopP)
	assert.Equal(t, topP, *cfg.TopP)
	assert.NotNil(t, cfg.TopK)
	assert.Equal(t, topK, *cfg.TopK)
	assert.NotNil(t, cfg.NumPredict)
	assert.Equal(t, numPredict, *cfg.NumPredict)
}

func TestOllamaConfigFromMapMissingModel(t *testing.T) {
	m := registry.Config{"host": "http://localhost:11434"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestOllamaConfigFromMapEnvHost(t *testing.T) {
	// Set env var for test
	os.Setenv("OLLAMA_HOST", "http://192.168.1.100:11434")
	defer os.Unsetenv("OLLAMA_HOST")

	m := registry.Config{"model": "gemma:7b"}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "http://192.168.1.100:11434", cfg.Host)
}

func TestOllamaConfigFunctionalOptions(t *testing.T) {
	temp := float64(0.5)
	topP := float64(0.95)
	topK := 100
	numPredict := 200

	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("llama2:13b"),
		WithHost("http://custom:11434"),
		WithTimeout(120*time.Second),
		WithTemperature(&temp),
		WithTopP(&topP),
		WithTopK(&topK),
		WithNumPredict(&numPredict),
	)

	assert.Equal(t, "llama2:13b", cfg.Model)
	assert.Equal(t, "http://custom:11434", cfg.Host)
	assert.Equal(t, 120*time.Second, cfg.Timeout)
	assert.NotNil(t, cfg.Temperature)
	assert.Equal(t, temp, *cfg.Temperature)
	assert.NotNil(t, cfg.TopP)
	assert.Equal(t, topP, *cfg.TopP)
	assert.NotNil(t, cfg.TopK)
	assert.Equal(t, topK, *cfg.TopK)
	assert.NotNil(t, cfg.NumPredict)
	assert.Equal(t, numPredict, *cfg.NumPredict)
}

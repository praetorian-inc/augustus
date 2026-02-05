package azure

import (
	"context"
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAzure_RequiresModel(t *testing.T) {
	cfg := Config{
		APIKey:   "test-key",
		Endpoint: "https://test.openai.azure.com",
	}

	_, err := NewAzureTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestNewAzure_RequiresAPIKey(t *testing.T) {
	cfg := Config{
		Model:    "gpt-4",
		Endpoint: "https://test.openai.azure.com",
	}

	_, err := NewAzureTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestNewAzure_RequiresEndpoint(t *testing.T) {
	cfg := Config{
		Model:  "gpt-4",
		APIKey: "test-key",
	}

	_, err := NewAzureTyped(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")
}

func TestNewAzure_Success(t *testing.T) {
	cfg := Config{
		Model:      "gpt-4",
		APIKey:     "test-key",
		Endpoint:   "https://test.openai.azure.com",
		APIVersion: "2024-06-01",
	}

	gen, err := NewAzureTyped(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, "azure.AzureOpenAI", gen.Name())
}

func TestNewAzure_FromEnvironment(t *testing.T) {
	// Set environment variables
	os.Setenv("AZURE_API_KEY", "env-key")
	os.Setenv("AZURE_ENDPOINT", "https://env.openai.azure.com")
	os.Setenv("AZURE_MODEL_NAME", "gpt-4")
	defer func() {
		os.Unsetenv("AZURE_API_KEY")
		os.Unsetenv("AZURE_ENDPOINT")
		os.Unsetenv("AZURE_MODEL_NAME")
	}()

	cfg := Config{}

	gen, err := NewAzureTyped(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
}

func TestAzureOpenAI_ModelMapping(t *testing.T) {
	tests := []struct {
		name          string
		inputModel    string
		expectedModel string
	}{
		{
			name:          "gpt-4 maps to gpt-4-turbo-2024-04-09",
			inputModel:    "gpt-4",
			expectedModel: "gpt-4-turbo-2024-04-09",
		},
		{
			name:          "gpt-35-turbo maps to gpt-3.5-turbo-0125",
			inputModel:    "gpt-35-turbo",
			expectedModel: "gpt-3.5-turbo-0125",
		},
		{
			name:          "unmapped model stays unchanged",
			inputModel:    "gpt-4o",
			expectedModel: "gpt-4o",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Model:      tt.inputModel,
				APIKey:     "test-key",
				Endpoint:   "https://test.openai.azure.com",
				APIVersion: "2024-06-01",
			}

			gen, err := NewAzureTyped(cfg)
			require.NoError(t, err)

			// Verify internal model was mapped correctly
			assert.Equal(t, tt.expectedModel, gen.model)
		})
	}
}

func TestAzureOpenAI_Generate_ChatModel(t *testing.T) {
	// Skip if no real credentials available
	if os.Getenv("AZURE_API_KEY") == "" {
		t.Skip("AZURE_API_KEY not set, skipping integration test")
	}

	cfg := Config{
		APIKey:     os.Getenv("AZURE_API_KEY"),
		Endpoint:   os.Getenv("AZURE_ENDPOINT"),
		Model:      os.Getenv("AZURE_MODEL_NAME"),
		APIVersion: "2024-06-01",
	}

	gen, err := NewAzureTyped(cfg)
	require.NoError(t, err)

	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{
				Prompt: attempt.NewUserMessage("Say hello"),
			},
		},
	}

	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.NotEmpty(t, responses[0].Content)
}

func TestAzureOpenAI_ClearHistory(t *testing.T) {
	cfg := Config{
		Model:    "gpt-4",
		APIKey:   "test-key",
		Endpoint: "https://test.openai.azure.com",
	}

	gen, err := NewAzureTyped(cfg)
	require.NoError(t, err)

	// Should not panic
	gen.ClearHistory()
}

func TestAzureOpenAI_Description(t *testing.T) {
	cfg := Config{
		Model:    "gpt-4",
		APIKey:   "test-key",
		Endpoint: "https://test.openai.azure.com",
	}

	gen, err := NewAzureTyped(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Azure")
}

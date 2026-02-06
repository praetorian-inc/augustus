package mistral

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMistralResponse creates a mock Mistral chat completion response.
// Mistral uses OpenAI-compatible format.
func mockMistralResponse(content string, n int) map[string]any {
	choices := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		choices[i] = map[string]any{
			"index": i,
			"message": map[string]any{
				"role":    "assistant",
				"content": content,
			},
			"finish_reason": "stop",
		}
	}
	return map[string]any{
		"id":      "chatcmpl-mistral-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "mistral-7b",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestMistralGenerator_Generate(t *testing.T) {
	// Create mock server that returns Mistral-formatted responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is a chat completion request
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "POST", r.Method)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockMistralResponse("Test response from Mistral", 1))
	}))
	defer server.Close()

	// Create generator with mock server
	gen, err := NewMistral(registry.Config{
		"model":    "mistral-7b",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err, "should create generator")

	// Create a simple conversation
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	// Generate response
	ctx := context.Background()
	responses, err := gen.Generate(ctx, conv, 1)

	// Verify
	require.NoError(t, err, "should generate response")
	require.Len(t, responses, 1, "should return 1 response")
	assert.Equal(t, "Test response from Mistral", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestMistralGenerator_RequiresModel(t *testing.T) {
	// Should error without model name
	_, err := NewMistral(registry.Config{
		"api_key": "test-key",
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestMistralGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("MISTRAL_API_KEY")
	os.Unsetenv("MISTRAL_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("MISTRAL_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewMistral(registry.Config{
		"model": "mistral-7b",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestMistralGenerator_MultipleResponses(t *testing.T) {
	// Create mock server that returns multiple choices
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockMistralResponse("Response", 3))
	}))
	defer server.Close()

	// Create generator
	gen, err := NewMistral(registry.Config{
		"model":    "mixtral-8x7b",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	// Generate multiple responses
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx := context.Background()
	responses, err := gen.Generate(ctx, conv, 3)

	// Verify
	require.NoError(t, err)
	require.Len(t, responses, 3, "should return 3 responses")
	for _, resp := range responses {
		assert.Equal(t, "Response", resp.Content)
		assert.Equal(t, attempt.RoleAssistant, resp.Role)
	}
}

func TestMistralGenerator_Name(t *testing.T) {
	gen, err := NewMistral(registry.Config{
		"model":   "mistral-large",
		"api_key": "test-key",
	})
	require.NoError(t, err)

	assert.Equal(t, "mistral.Mistral", gen.Name())
}

func TestMistralGenerator_Description(t *testing.T) {
	gen, err := NewMistral(registry.Config{
		"model":   "mistral-7b",
		"api_key": "test-key",
	})
	require.NoError(t, err)

	desc := gen.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Mistral")
}

func TestMistralGenerator_Registration(t *testing.T) {
	// Verify the generator is registered
	factory, ok := generators.Get("mistral.Mistral")
	assert.True(t, ok, "mistral.Mistral should be registered")
	assert.NotNil(t, factory)

	// Verify it can be created via registry
	gen, err := generators.Create("mistral.Mistral", registry.Config{
		"model":   "mistral-7b",
		"api_key": "test-key",
	})
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, "mistral.Mistral", gen.Name())
}

func TestNewMistralTyped(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockMistralResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("mistral-large"),
		WithAPIKey("test-typed-key"),
		WithTemperature(0.3),
		WithBaseURL(server.URL),
	)

	// NewMistralTyped takes typed config directly
	g, err := NewMistralTyped(cfg)
	require.NoError(t, err)
	assert.Equal(t, "mistral-large", g.model)
	assert.Equal(t, float32(0.3), g.temperature)
}

func TestNewMistralWithOptions(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockMistralResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// NewMistralWithOptions uses functional options
	g, err := NewMistralWithOptions(
		WithModel("mistral-7b"),
		WithAPIKey("test-options-key"),
		WithMaxTokens(2048),
		WithBaseURL(server.URL),
	)
	require.NoError(t, err)
	assert.Equal(t, "mistral-7b", g.model)
	assert.Equal(t, 2048, g.maxTokens)
}

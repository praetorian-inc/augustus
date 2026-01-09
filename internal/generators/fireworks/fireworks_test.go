package fireworks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFireworksResponse creates a mock Fireworks chat completion response (OpenAI-compatible format).
func mockFireworksResponse(content string, n int) map[string]any {
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
		"id":      "chatcmpl-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestFireworksGenerator_RequiresModel(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("response", 1))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewFireworks(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestFireworksGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("FIREWORKS_API_KEY")
	os.Unsetenv("FIREWORKS_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("FIREWORKS_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewFireworks(registry.Config{
		"model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestFireworksGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("FIREWORKS_API_KEY")
	os.Setenv("FIREWORKS_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("FIREWORKS_API_KEY", origKey)
		} else {
			os.Unsetenv("FIREWORKS_API_KEY")
		}
	}()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestFireworksGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "fireworks.Fireworks", g.Name())
}

func TestFireworksGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Fireworks")
}

func TestFireworksGenerator_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify chat completions endpoint
		assert.True(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Hello from Fireworks!", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Fireworks!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestFireworksGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	assert.Len(t, responses, 3)
	for i, resp := range responses {
		assert.Equal(t, "Response", resp.Content, "response %d content mismatch", i)
	}
}

func TestFireworksGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant.")
	conv.AddPrompt("Hello!")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify system message is included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(messages), 2)

	firstMsg := messages[0].(map[string]any)
	assert.Equal(t, "system", firstMsg["role"])
	assert.Equal(t, "You are a helpful assistant.", firstMsg["content"])
}

func TestFireworksGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":      "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":    "test-key",
		"base_url":   server.URL,
		"max_tokens": 100,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, float64(100), receivedRequest["max_tokens"])
}

func TestFireworksGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":       "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"temperature": 0.5,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, 0.5, receivedRequest["temperature"])
}

func TestFireworksGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
	assert.Len(t, responses, 1)
}

func TestFireworksGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("fireworks.Fireworks")
	assert.True(t, ok, "fireworks.Fireworks should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "fireworks.Fireworks", g.Name())
}

func TestFireworksGenerator_SupportedModels(t *testing.T) {
	models := []string{
		"accounts/fireworks/models/llama-v3p1-70b-instruct",
		"accounts/fireworks/models/mixtral-8x7b-instruct",
		"accounts/fireworks/models/qwen2p5-72b-instruct",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
			}))
			defer server.Close()

			g, err := NewFireworks(registry.Config{
				"model":    model,
				"api_key":  "test-key",
				"base_url": server.URL,
			})
			require.NoError(t, err)

			conv := attempt.NewConversation()
			conv.AddPrompt("test")

			_, err = g.Generate(context.Background(), conv, 1)
			assert.NoError(t, err)
		})
	}
}

func TestFireworksGenerator_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Internal server error",
				"type":    "server_error",
			},
		})
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "fireworks")
}

func TestFireworksGenerator_Generate_ZeroN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockFireworksResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewFireworks(registry.Config{
		"model":    "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 0)
	require.NoError(t, err)
	assert.Empty(t, responses)
}

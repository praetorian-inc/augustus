package together

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

// mockTogetherResponse creates a mock Together AI chat completion response.
// Together AI uses OpenAI-compatible format.
func mockTogetherResponse(content string, n int) map[string]any {
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
		"id":      "together-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "meta-llama/Llama-2-70b-chat-hf",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestTogetherGenerator_RequiresModel(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("response", 1))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewTogether(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestTogetherGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("TOGETHER_API_KEY")
	os.Unsetenv("TOGETHER_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("TOGETHER_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewTogether(registry.Config{
		"model": "meta-llama/Llama-2-70b-chat-hf",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestTogetherGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("TOGETHER_API_KEY")
	os.Setenv("TOGETHER_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("TOGETHER_API_KEY", origKey)
		} else {
			os.Unsetenv("TOGETHER_API_KEY")
		}
	}()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestTogetherGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "together.Together", g.Name())
}

func TestTogetherGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Together")
}

func TestTogetherGenerator_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify chat endpoint (OpenAI-compatible)
		assert.True(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Hello from Llama!", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Llama!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestTogetherGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
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

func TestTogetherGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
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

func TestTogetherGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":       "meta-llama/Llama-2-70b-chat-hf",
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

func TestTogetherGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":      "meta-llama/Llama-2-70b-chat-hf",
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

func TestTogetherGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
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

func TestTogetherGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("together.Together")
	assert.True(t, ok, "together.Together should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "together.Together", g.Name())
}

func TestTogetherGenerator_SupportedModels(t *testing.T) {
	supportedModels := []string{
		"meta-llama/Llama-2-70b-chat-hf",
		"meta-llama/CodeLlama-34b-Instruct-hf",
		"mistralai/Mistral-7B-Instruct-v0.1",
	}

	for _, model := range supportedModels {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
			}))
			defer server.Close()

			g, err := NewTogether(registry.Config{
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

func TestTogetherGenerator_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockTogetherResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewTogether(registry.Config{
		"model":    "meta-llama/Llama-2-70b-chat-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 0)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

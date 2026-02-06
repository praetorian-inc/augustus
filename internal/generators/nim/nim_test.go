package nim

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

// mockNIMResponse creates a mock NIM chat completion response (OpenAI-compatible format).
func mockNIMResponse(content string, n int) map[string]any {
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
		"id":      "chatcmpl-nim-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "meta/llama-2-70b-chat",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestNIMGenerator_RequiresModel(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewNIM(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestNIMGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("NIM_API_KEY")
	os.Unsetenv("NIM_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("NIM_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewNIM(registry.Config{
		"model": "meta/llama-2-70b-chat",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestNIMGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("NIM_API_KEY")
	os.Setenv("NIM_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("NIM_API_KEY", origKey)
		} else {
			os.Unsetenv("NIM_API_KEY")
		}
	}()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestNIMGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nim.NIM", g.Name())
}

func TestNIMGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "NIM")
}

func TestNIMGenerator_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify chat endpoint
		assert.True(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Hello from NIM!", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from NIM!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestNIMGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
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

func TestNIMGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
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

func TestNIMGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":       "meta/llama-2-70b-chat",
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

func TestNIMGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":      "meta/llama-2-70b-chat",
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

func TestNIMGenerator_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
		"top_p":    0.9,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, 0.9, receivedRequest["top_p"])
}

func TestNIMGenerator_SupportedModels(t *testing.T) {
	models := []string{
		"meta/llama-2-70b-chat",
		"meta/llama-2-13b-chat",
		"meta/llama-2-7b-chat",
		"mistralai/mixtral-8x7b-instruct-v0.1",
		"mistralai/mixtral-8x22b-instruct-v0.1",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
			}))
			defer server.Close()

			g, err := NewNIM(registry.Config{
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

func TestNIMGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
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

func TestNIMGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("nim.NIM")
	assert.True(t, ok, "nim.NIM should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nim.NIM", g.Name())
}

func TestNIMGenerator_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
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

func TestNIMGenerator_NegativeGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNIM(registry.Config{
		"model":    "meta/llama-2-70b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, -1)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

package cohere

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockChatResponse creates a mock Cohere v2 chat response.
func mockChatResponse(content string) map[string]any {
	return map[string]any{
		"id":           "chat-test-id",
		"finish_reason": "COMPLETE",
		"message": map[string]any{
			"role": "assistant",
			"content": []map[string]any{
				{
					"type": "text",
					"text": content,
				},
			},
		},
		"usage": map[string]any{
			"billed_units": map[string]any{
				"input_tokens":  10,
				"output_tokens": 20,
			},
			"tokens": map[string]any{
				"input_tokens":  10,
				"output_tokens": 20,
			},
		},
	}
}

// mockGenerateResponse creates a mock Cohere v1 generate response.
func mockGenerateResponse(content string, n int) map[string]any {
	generations := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		generations[i] = map[string]any{
			"id":            "gen-test-id",
			"text":          content,
			"finish_reason": "COMPLETE",
		}
	}
	return map[string]any{
		"id":          "generate-test-id",
		"generations": generations,
		"meta": map[string]any{
			"api_version": map[string]any{
				"version": "1",
			},
		},
	}
}

func TestCohereGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("COHERE_API_KEY")
	os.Unsetenv("COHERE_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("COHERE_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewCohere(registry.Config{
		"model": "command",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestCohereGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("COHERE_API_KEY")
	os.Setenv("COHERE_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("COHERE_API_KEY", origKey)
		} else {
			os.Unsetenv("COHERE_API_KEY")
		}
	}()

	g, err := NewCohere(registry.Config{
		"model":    "command",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestCohereGenerator_APIKeyFromConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-config-key", auth)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	// Clear env var to ensure config is used
	origKey := os.Getenv("COHERE_API_KEY")
	os.Unsetenv("COHERE_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("COHERE_API_KEY", origKey)
		}
	}()

	g, err := NewCohere(registry.Config{
		"model":    "command",
		"api_key":  "test-config-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestCohereGenerator_DefaultModel(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
		// No model specified - should default to "command"
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, "command", receivedRequest["model"])
}

func TestCohereGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "cohere.Cohere", g.Name())
}

func TestCohereGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Cohere")
}

func TestCohereGenerator_Generate_V2Chat(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Should use v2 chat endpoint
		assert.Contains(t, r.URL.Path, "chat")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Hello from Cohere!"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v2",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Cohere!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestCohereGenerator_Generate_V1Legacy(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Should use v1 generate endpoint
		assert.Contains(t, r.URL.Path, "generate")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("Legacy response", 1))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v1",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test prompt")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Legacy response", responses[0].Content)
}

func TestCohereGenerator_Generate_DefaultsToV2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should default to v2 chat
		assert.Contains(t, r.URL.Path, "chat")
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command",
		"api_key":  "test-key",
		"base_url": server.URL,
		// No api_version - should default to v2
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestCohereGenerator_Generate_MultipleResponses(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v2",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// v2 Chat API doesn't support num_generations, so requires multiple calls
	assert.Len(t, responses, 3)
	assert.Equal(t, 3, requestCount)
}

func TestCohereGenerator_Generate_V1MultipleGenerations(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		n := 1
		if nVal, ok := receivedRequest["num_generations"].(float64); ok {
			n = int(nVal)
		}

		_ = json.NewEncoder(w).Encode(mockGenerateResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v1",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// v1 Generate API supports num_generations natively
	assert.Len(t, responses, 3)
}

func TestCohereGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v2",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant.")
	conv.AddPrompt("Hello!")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// System message should be in messages array for v2 chat
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(messages), 2)

	firstMsg := messages[0].(map[string]any)
	assert.Equal(t, "system", firstMsg["role"])
	assert.Equal(t, "You are a helpful assistant.", firstMsg["content"])
}

func TestCohereGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
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

func TestCohereGenerator_Generate_DefaultTemperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
		// No temperature - should use default 0.75
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Default temperature from Python: 0.75
	if temp, ok := receivedRequest["temperature"].(float64); ok {
		assert.InDelta(t, 0.75, temp, 0.01)
	}
}

func TestCohereGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":      "command-r",
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

func TestCohereGenerator_Generate_TopK(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
		"k":        50,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, float64(50), receivedRequest["k"])
}

func TestCohereGenerator_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
		"p":        0.9,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, 0.9, receivedRequest["p"])
}

func TestCohereGenerator_Generate_FrequencyPenalty(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":             "command-r",
		"api_key":           "test-key",
		"base_url":          server.URL,
		"frequency_penalty": 0.5,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, 0.5, receivedRequest["frequency_penalty"])
}

func TestCohereGenerator_Generate_PresencePenalty(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":            "command-r",
		"api_key":          "test-key",
		"base_url":         server.URL,
		"presence_penalty": 0.3,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, 0.3, receivedRequest["presence_penalty"])
}

func TestCohereGenerator_Generate_EmptyPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Empty prompts should be handled gracefully
		_ = json.NewEncoder(w).Encode(mockChatResponse(""))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
}

func TestCohereGenerator_Generate_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
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

func TestCohereGenerator_Generate_NegativeGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
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

func TestCohereGenerator_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "rate limit exceeded",
		})
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "rate")
}

func TestCohereGenerator_Generate_BadRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "invalid request",
		})
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestCohereGenerator_Generate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "internal server error",
		})
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestCohereGenerator_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = g.Generate(ctx, conv, 1)
	assert.Error(t, err)
}

func TestCohereGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":    "command-r",
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

func TestCohereGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("cohere.Cohere")
	assert.True(t, ok, "cohere.Cohere should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "command-r",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "cohere.Cohere", g.Name())
}

func TestCohereGenerator_MultiTurnConversation(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "v2",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are helpful.")
	conv.AddTurn(attempt.NewTurn("Hello!").WithResponse("Hi there!"))
	conv.AddPrompt("How are you?")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify all messages are included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	// Should have: system + user + assistant + user = 4 messages
	assert.Len(t, messages, 4)
}

func TestCohereGenerator_SupportedModels(t *testing.T) {
	models := []string{
		"command",
		"command-r",
		"command-r-plus",
		"command-light",
		"command-nightly",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
			}))
			defer server.Close()

			g, err := NewCohere(registry.Config{
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

func TestCohereGenerator_InvalidAPIVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should default to v2 chat endpoint when invalid version provided
		assert.Contains(t, r.URL.Path, "chat")
		_ = json.NewEncoder(w).Encode(mockChatResponse("Response"))
	}))
	defer server.Close()

	g, err := NewCohere(registry.Config{
		"model":       "command-r",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"api_version": "invalid",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

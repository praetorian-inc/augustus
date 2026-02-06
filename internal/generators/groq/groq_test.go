package groq

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

// mockGroqResponse creates a mock Groq chat completion response (OpenAI-compatible format).
func mockGroqResponse(content string, n int) map[string]any {
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
		"model":   "llama-3.1-70b-versatile",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestGroqGenerator_RequiresModel(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("response", 1))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewGroq(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestGroqGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("GROQ_API_KEY")
	os.Unsetenv("GROQ_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("GROQ_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewGroq(registry.Config{
		"model": "llama-3.1-70b-versatile",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestGroqGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("GROQ_API_KEY")
	os.Setenv("GROQ_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("GROQ_API_KEY", origKey)
		} else {
			os.Unsetenv("GROQ_API_KEY")
		}
	}()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestGroqGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGroqResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "groq.Groq", g.Name())
}

func TestGroqGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGroqResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Groq")
}

func TestGroqGenerator_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify chat completions endpoint
		assert.True(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Hello from Groq!", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Groq!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestGroqGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
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

func TestGroqGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
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

func TestGroqGenerator_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Rate limit exceeded",
				"type":    "rate_limit_error",
			},
		})
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
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

func TestGroqGenerator_Generate_RateLimitWithBackoff(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			// First 2 calls return rate limit
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "Rate limit exceeded",
					"type":    "rate_limit_error",
				},
			})
		} else {
			// Third call succeeds
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockGroqResponse("Success after retry", 1))
		}
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":      "llama-3.1-70b-versatile",
		"api_key":    "test-key",
		"base_url":   server.URL,
		"max_retries": 3,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "Success after retry", responses[0].Content)
	assert.Equal(t, 3, callCount, "should have retried 2 times before success")
}

func TestGroqGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":      "llama-3.1-70b-versatile",
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

func TestGroqGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":       "llama-3.1-70b-versatile",
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

func TestGroqGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
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

func TestGroqGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("groq.Groq")
	assert.True(t, ok, "groq.Groq should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "llama-3.1-70b-versatile",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "groq.Groq", g.Name())
}

func TestGroqGenerator_SupportedModels(t *testing.T) {
	models := []string{
		"llama-3.1-70b-versatile",
		"mixtral-8x7b-32768",
		"gemma-7b-it",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
			}))
			defer server.Close()

			g, err := NewGroq(registry.Config{
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

func TestGroqGenerator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockGroqResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewGroq(registry.Config{
		"model":    "llama-3.1-70b-versatile",
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

func TestNewGroqTyped(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockGroqResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("llama-3.1-70b-versatile"),
		WithAPIKey("test-typed-key"),
		WithTemperature(0.3),
		WithBaseURL(server.URL),
	)

	// NewGroqTyped takes typed config directly
	g, err := NewGroqTyped(cfg)
	require.NoError(t, err)
	assert.Equal(t, "llama-3.1-70b-versatile", g.model)
	assert.Equal(t, float32(0.3), g.temperature)
}

func TestNewGroqWithOptions(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockGroqResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// NewGroqWithOptions uses functional options
	g, err := NewGroqWithOptions(
		WithModel("llama-3.1-70b-versatile"),
		WithAPIKey("test-options-key"),
		WithMaxTokens(2048),
		WithBaseURL(server.URL),
	)
	require.NoError(t, err)
	assert.Equal(t, "llama-3.1-70b-versatile", g.model)
	assert.Equal(t, 2048, g.maxTokens)
}

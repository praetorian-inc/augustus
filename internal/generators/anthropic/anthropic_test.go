package anthropic

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

// mockAnthropicResponse creates a mock Anthropic Messages API response.
func mockAnthropicResponse(content string) map[string]any {
	return map[string]any{
		"id":    "msg_test123",
		"type":  "message",
		"role":  "assistant",
		"model": "claude-3-opus-20240229",
		"content": []map[string]any{
			{
				"type": "text",
				"text": content,
			},
		},
		"stop_reason":  "end_turn",
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  10,
			"output_tokens": 20,
		},
	}
}

func TestAnthropicGenerator_RequiresModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("response"))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewAnthropic(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestAnthropicGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("ANTHROPIC_API_KEY")
	os.Unsetenv("ANTHROPIC_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("ANTHROPIC_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewAnthropic(registry.Config{
		"model": "claude-3-opus-20240229",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestAnthropicGenerator_APIKeyFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify x-api-key header (Anthropic uses this instead of Authorization Bearer)
		apiKey := r.Header.Get("x-api-key")
		assert.Equal(t, "test-env-key", apiKey)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("response"))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("ANTHROPIC_API_KEY")
	os.Setenv("ANTHROPIC_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("ANTHROPIC_API_KEY", origKey)
		} else {
			os.Unsetenv("ANTHROPIC_API_KEY")
		}
	}()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestAnthropicGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "anthropic.Anthropic", g.Name())
}

func TestAnthropicGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Anthropic")
}

func TestAnthropicGenerator_Generate_SingleResponse(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify it's the messages endpoint
		assert.Contains(t, r.URL.Path, "messages")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Hello, I am Claude!"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello, I am Claude!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format - Anthropic uses messages array
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestAnthropicGenerator_Generate_MultipleResponses(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Anthropic doesn't support n parameter, so we need multiple calls
	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	assert.Len(t, responses, 3)
	// Should have made 3 API calls
	assert.Equal(t, 3, callCount)
}

func TestAnthropicGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant.")
	conv.AddPrompt("Hello!")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Anthropic uses separate system parameter (not in messages array)
	system, ok := receivedRequest["system"].(string)
	require.True(t, ok, "should have system parameter")
	assert.Equal(t, "You are a helpful assistant.", system)

	// Messages should NOT include system message
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	assert.Len(t, messages, 1) // Only the user message
}

func TestAnthropicGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":       "claude-3-opus-20240229",
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

func TestAnthropicGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":      "claude-3-opus-20240229",
		"api_key":    "test-key",
		"base_url":   server.URL,
		"max_tokens": 200,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, float64(200), receivedRequest["max_tokens"])
}

func TestAnthropicGenerator_Generate_DefaultMaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
		// No max_tokens specified - should use default
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Anthropic requires max_tokens, should have a sensible default
	maxTokens, ok := receivedRequest["max_tokens"].(float64)
	assert.True(t, ok, "max_tokens should be present")
	assert.Greater(t, maxTokens, float64(0), "max_tokens should be positive")
}

func TestAnthropicGenerator_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_Generate_TopK(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
		"top_k":    40,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, float64(40), receivedRequest["top_k"])
}

func TestAnthropicGenerator_Generate_StopSequences(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":          "claude-3-opus-20240229",
		"api_key":        "test-key",
		"base_url":       server.URL,
		"stop_sequences": []any{"\n\nHuman:", "\n\nAssistant:"},
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	stop, ok := receivedRequest["stop_sequences"].([]any)
	require.True(t, ok)
	assert.Contains(t, stop, "\n\nHuman:")
	assert.Contains(t, stop, "\n\nAssistant:")
}

func TestAnthropicGenerator_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "rate_limit_error",
				"message": "Rate limit exceeded",
			},
		})
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_Generate_BadRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "invalid_request_error",
				"message": "Invalid request",
			},
		})
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestAnthropicGenerator_Generate_AuthenticationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "authentication_error",
				"message": "Invalid API key",
			},
		})
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "authentication")
}

func TestAnthropicGenerator_Generate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "Internal server error",
			},
		})
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestAnthropicGenerator_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("anthropic.Anthropic")
	assert.True(t, ok, "anthropic.Anthropic should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "anthropic.Anthropic", g.Name())
}

func TestAnthropicGenerator_MultiTurnConversation(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are helpful.")
	conv.AddTurn(attempt.NewTurn("Hello!").WithResponse("Hi there!"))
	conv.AddPrompt("How are you?")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify system is separate
	system, ok := receivedRequest["system"].(string)
	require.True(t, ok)
	assert.Equal(t, "You are helpful.", system)

	// Verify all messages are included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	// Should have: user + assistant + user = 3 messages (no system in messages)
	assert.Len(t, messages, 3)
}

func TestAnthropicGenerator_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_NegativeGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
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

func TestAnthropicGenerator_ClaudeModels(t *testing.T) {
	claudeModels := []string{
		"claude-3-opus-20240229",
		"claude-3-sonnet-20240229",
		"claude-3-haiku-20240307",
		"claude-3-5-sonnet-20241022",
		"claude-3-5-haiku-20241022",
	}

	for _, model := range claudeModels {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.Path, "messages")
				_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
			}))
			defer server.Close()

			g, err := NewAnthropic(registry.Config{
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

func TestAnthropicGenerator_DefaultTemperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
		// No temperature specified - should use default
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Default temperature should match litellm pattern (0.7)
	if temp, ok := receivedRequest["temperature"].(float64); ok {
		assert.InDelta(t, 0.7, temp, 0.01)
	}
}

func TestAnthropicGenerator_AnthropicVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify anthropic-version header is set
		version := r.Header.Get("anthropic-version")
		assert.NotEmpty(t, version, "anthropic-version header should be set")

		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Response"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model":    "claude-3-opus-20240229",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

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
		"stop_reason":   "end_turn",
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
	_ = os.Unsetenv("ANTHROPIC_API_KEY")
	defer func() {
		if origKey != "" {
			_ = os.Setenv("ANTHROPIC_API_KEY", origKey)
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
	t.Setenv("ANTHROPIC_API_KEY", "test-env-key")

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

// ---------------------------------------------------------------------------
// Group 4: Anthropic Generator Tool Wiring
// ---------------------------------------------------------------------------

func TestAnthropicGenerator_Generate_WithTools(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("I will search"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety")
	conv.Tools = []map[string]any{{
		"name":        "web_search",
		"description": "Search the web",
		"parameters":  map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}},
	}}
	conv.ToolChoice = "auto"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	tools, ok := receivedRequest["tools"].([]any)
	require.True(t, ok)
	require.Len(t, tools, 1)

	tool := tools[0].(map[string]any)
	assert.Equal(t, "web_search", tool["name"])
	assert.Equal(t, "Search the web", tool["description"])
	// Anthropic uses "input_schema" not "parameters"
	assert.NotNil(t, tool["input_schema"])

	tc := receivedRequest["tool_choice"].(map[string]any)
	assert.Equal(t, "auto", tc["type"])
}

func TestAnthropicGenerator_Generate_ToolChoiceRequired(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Searching"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "required"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	tc := receivedRequest["tool_choice"].(map[string]any)
	assert.Equal(t, "any", tc["type"], "required should map to Anthropic 'any'")
}

func TestAnthropicGenerator_Generate_ToolChoiceNone(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Hello"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "none"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Anthropic doesn't have "none" -- tools should be stripped entirely
	_, hasTools := receivedRequest["tools"]
	assert.False(t, hasTools, "tool_choice 'none' should strip tools for Anthropic")
	_, hasTC := receivedRequest["tool_choice"]
	assert.False(t, hasTC, "tool_choice should also be stripped")
}

func TestAnthropicGenerator_Generate_ToolChoiceByName(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Searching"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "web_search"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	tc := receivedRequest["tool_choice"].(map[string]any)
	assert.Equal(t, "tool", tc["type"])
	assert.Equal(t, "web_search", tc["name"])
}

func TestAnthropicGenerator_Generate_ResponseToolUseBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant",
			"model": "claude-3-5-sonnet-20241022",
			"content": []map[string]any{
				{"type": "text", "text": "Let me search for that."},
				{"type": "tool_use", "id": "toolu_abc123", "name": "web_search",
					"input": map[string]any{"query": "AI safety"}},
			},
			"stop_reason": "tool_use",
			"usage":       map[string]any{"input_tokens": 10, "output_tokens": 20},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	assert.Equal(t, "Let me search for that.", responses[0].Content)
	require.NotNil(t, responses[0].ToolCalls)
	require.Len(t, responses[0].ToolCalls, 1)
	assert.Equal(t, "web_search", responses[0].ToolCalls[0]["name"])
	assert.Equal(t, "toolu_abc123", responses[0].ToolCalls[0]["id"])
	args := responses[0].ToolCalls[0]["args"].(map[string]any)
	assert.Equal(t, "AI safety", args["query"])
}

func TestAnthropicGenerator_Generate_ToolsMissingParameters(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("OK"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")
	conv.Tools = []map[string]any{{"name": "noop", "description": "Does nothing"}}
	// No "parameters" key

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	tools := receivedRequest["tools"].([]any)
	tool := tools[0].(map[string]any)
	schema := tool["input_schema"].(map[string]any)
	assert.Equal(t, "object", schema["type"], "missing parameters should get default {type: object}")
}

// ---------------------------------------------------------------------------
// Group 9: Anthropic Tool-Result Wire Format
// ---------------------------------------------------------------------------

func TestAnthropicConversationToMessages_ToolResult(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Follow-up"))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	// Build a 2-turn conversation with tool result
	conv := attempt.NewConversation()
	conv.AddPrompt("Search for info")

	// Turn 1 response with tool calls
	turn1Resp := attempt.NewAssistantMessage("")
	turn1Resp.ToolCalls = []map[string]any{
		{"name": "web_search", "id": "toolu_abc", "args": map[string]any{"query": "test"}},
	}
	conv.Turns[0].Response = &turn1Resp

	// Tool result turn
	toolResult := attempt.NewToolResultMessage("toolu_abc", "Search results here")
	conv.AddTurn(attempt.Turn{Prompt: toolResult})

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	messages := receivedRequest["messages"].([]any)
	// Expected: user, assistant (structured), user (tool_result)
	require.Len(t, messages, 3)

	// First: plain user message
	msg0 := messages[0].(map[string]any)
	assert.Equal(t, "user", msg0["role"])

	// Second: assistant with tool_use content blocks
	msg1 := messages[1].(map[string]any)
	assert.Equal(t, "assistant", msg1["role"])
	content1 := msg1["content"].([]any)
	toolUseBlock := content1[0].(map[string]any)
	assert.Equal(t, "tool_use", toolUseBlock["type"])
	assert.Equal(t, "web_search", toolUseBlock["name"])

	// Third: user with tool_result content block
	msg2 := messages[2].(map[string]any)
	assert.Equal(t, "user", msg2["role"])
	content2 := msg2["content"].([]any)
	toolResultBlock := content2[0].(map[string]any)
	assert.Equal(t, "tool_result", toolResultBlock["type"])
	assert.Equal(t, "toolu_abc", toolResultBlock["tool_use_id"])
	assert.Equal(t, "Search results here", toolResultBlock["content"])
}

// TestAnthropicConversationToMessages_ParallelToolResultsCoalesced tests the bug
// described in PR #131: when the model returns ≥2 tool calls in Turn 1,
// RunTwoTurnPrompts adds a separate RoleTool turn for each. conversationToMessages
// must coalesce all consecutive RoleTool turns into a SINGLE user message with
// all tool_result blocks, because Anthropic rejects consecutive same-role messages
// (HTTP 400). The existing TestAnthropicConversationToMessages_ToolResult only
// tests the single-tool case and does not cover this.
func TestAnthropicConversationToMessages_ParallelToolResultsCoalesced(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockAnthropicResponse("Here are the results."))
	}))
	defer server.Close()

	g, err := NewAnthropic(registry.Config{
		"model": "claude-3-5-sonnet-20241022", "api_key": "test-key", "base_url": server.URL,
	})
	require.NoError(t, err)

	// Build a conversation that simulates what RunTwoTurnPrompts produces
	// when the model returns 2 tool calls: TWO separate RoleTool turns
	// (one per call), which is the shape RunTwoTurnPrompts adds them.
	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety and climate change")

	// Turn 1 response: assistant with 2 tool_use blocks
	turn1Resp := attempt.NewAssistantMessage("")
	turn1Resp.ToolCalls = []map[string]any{
		{"name": "web_search", "id": "toolu_001", "args": map[string]any{"query": "AI safety"}},
		{"name": "web_search", "id": "toolu_002", "args": map[string]any{"query": "climate change"}},
	}
	conv.Turns[0].Response = &turn1Resp

	// Two separate RoleTool turns — exactly what RunTwoTurnPrompts adds
	conv.AddTurn(attempt.Turn{Prompt: attempt.NewToolResultMessage("toolu_001", "AI safety results")})
	conv.AddTurn(attempt.Turn{Prompt: attempt.NewToolResultMessage("toolu_002", "Climate results")})

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok, "request must contain messages array")

	// With coalescing, the structure must be:
	//   [0] user (original prompt)
	//   [1] assistant (tool_use blocks)
	//   [2] user (SINGLE message with BOTH tool_result blocks)
	// NOT 4 messages (with two separate user tool-result messages).
	require.Len(t, messages, 3,
		"parallel tool results must be coalesced into a single user message (not separate consecutive user messages)")

	msg2 := messages[2].(map[string]any)
	assert.Equal(t, "user", msg2["role"])
	content2, ok := msg2["content"].([]any)
	require.True(t, ok, "coalesced user message must have structured content")
	require.Len(t, content2, 2, "coalesced user message must contain both tool_result blocks")

	block0 := content2[0].(map[string]any)
	assert.Equal(t, "tool_result", block0["type"])
	assert.Equal(t, "toolu_001", block0["tool_use_id"])
	assert.Equal(t, "AI safety results", block0["content"])

	block1 := content2[1].(map[string]any)
	assert.Equal(t, "tool_result", block1["type"])
	assert.Equal(t, "toolu_002", block1["tool_use_id"])
	assert.Equal(t, "Climate results", block1["content"])
}

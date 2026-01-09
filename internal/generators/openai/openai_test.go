package openai

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

// mockOpenAIResponse creates a mock OpenAI chat completion response.
func mockOpenAIResponse(content string, n int) map[string]any {
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
		"model":   "gpt-4",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

// mockCompletionResponse creates a mock OpenAI completion response.
func mockCompletionResponse(content string, n int) map[string]any {
	choices := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		choices[i] = map[string]any{
			"index":         i,
			"text":          content,
			"finish_reason": "stop",
		}
	}
	return map[string]any{
		"id":      "cmpl-test",
		"object":  "text_completion",
		"created": 1234567890,
		"model":   "gpt-3.5-turbo-instruct",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestOpenAIGenerator_RequiresModel(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("response", 1))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewOpenAI(registry.Config{
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestOpenAIGenerator_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("OPENAI_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("OPENAI_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewOpenAI(registry.Config{
		"model": "gpt-4",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestOpenAIGenerator_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("OPENAI_API_KEY")
	os.Setenv("OPENAI_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("OPENAI_API_KEY", origKey)
		} else {
			os.Unsetenv("OPENAI_API_KEY")
		}
	}()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestOpenAIGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "openai.OpenAI", g.Name())
}

func TestOpenAIGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "OpenAI")
}

func TestOpenAIGenerator_Generate_ChatModel(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify chat endpoint
		assert.True(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Hello, I am GPT!", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello, I am GPT!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestOpenAIGenerator_Generate_CompletionModel(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Check if it's completions endpoint (not chat)
		if strings.Contains(r.URL.Path, "completions") && !strings.Contains(r.URL.Path, "chat") {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockCompletionResponse("Completion response", 1))
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Chat response", 1))
		}
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-3.5-turbo-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Complete this:")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	// Completion models should use the prompt field
	if prompt, ok := receivedRequest["prompt"]; ok {
		assert.NotEmpty(t, prompt)
	}
}

func TestOpenAIGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":       "gpt-4",
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

func TestOpenAIGenerator_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":      "gpt-4",
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

func TestOpenAIGenerator_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_Generate_FrequencyPenalty(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":             "gpt-4",
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

func TestOpenAIGenerator_Generate_PresencePenalty(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":            "gpt-4",
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

func TestOpenAIGenerator_Generate_StopSequences(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
		"stop":     []any{"#", ";"},
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	stop, ok := receivedRequest["stop"].([]any)
	require.True(t, ok)
	assert.Contains(t, stop, "#")
	assert.Contains(t, stop, ";")
}

func TestOpenAIGenerator_Generate_RateLimitError(t *testing.T) {
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

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_Generate_BadRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Invalid request",
				"type":    "invalid_request_error",
			},
		})
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestOpenAIGenerator_Generate_ServerError(t *testing.T) {
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

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestOpenAIGenerator_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("openai.OpenAI")
	assert.True(t, ok, "openai.OpenAI should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "openai.OpenAI", g.Name())
}

func TestOpenAIGenerator_MultiTurnConversation(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

	// Verify all messages are included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	// Should have: system + user + assistant + user = 4 messages
	assert.Len(t, messages, 4)
}

func TestOpenAIGenerator_EmptyConversation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	// Empty conversation - no turns

	_, _ = g.Generate(context.Background(), conv, 1)
	// Should handle gracefully (either error or empty result)
	// The exact behavior depends on implementation choice
}

func TestOpenAIGenerator_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_NegativeGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
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

func TestOpenAIGenerator_DefaultTemperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "gpt-4",
		"api_key":  "test-key",
		"base_url": server.URL,
		// No temperature specified - should use default
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Default temperature should be 0.7 (from Python)
	if temp, ok := receivedRequest["temperature"].(float64); ok {
		assert.InDelta(t, 0.7, temp, 0.01)
	}
}

func TestOpenAIGenerator_ChatModels(t *testing.T) {
	chatModels := []string{
		"gpt-4",
		"gpt-4-turbo",
		"gpt-4o",
		"gpt-4o-mini",
		"gpt-3.5-turbo",
	}

	for _, model := range chatModels {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Should use chat completions endpoint
				assert.Contains(t, r.URL.Path, "chat/completions")
				_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
			}))
			defer server.Close()

			g, err := NewOpenAI(registry.Config{
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

func TestOpenAIGenerator_CompletionModels(t *testing.T) {
	completionModels := []string{
		"gpt-3.5-turbo-instruct",
		"davinci-002",
		"babbage-002",
	}

	for _, model := range completionModels {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Completion models use completions endpoint
				if strings.Contains(r.URL.Path, "completions") && !strings.Contains(r.URL.Path, "chat") {
					_ = json.NewEncoder(w).Encode(mockCompletionResponse("Response", 1))
				} else {
					_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
				}
			}))
			defer server.Close()

			g, err := NewOpenAI(registry.Config{
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

func TestOpenAIGenerator_UnknownModelDefaultsToChat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Unknown models should default to chat completions
		assert.Contains(t, r.URL.Path, "chat/completions")
		_ = json.NewEncoder(w).Encode(mockOpenAIResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewOpenAI(registry.Config{
		"model":    "unknown-model-xyz",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestNewOpenAITyped(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockOpenAIResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("gpt-4"),
		WithAPIKey("sk-test-typed"),
		WithTemperature(0.3),
		WithBaseURL(server.URL),
	)

	// NewOpenAITyped takes typed config directly
	g, err := NewOpenAITyped(cfg)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", g.model)
	assert.Equal(t, float32(0.3), g.temperature)
}

func TestNewOpenAIWithOptions(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mockOpenAIResponse("Test response", 1)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// NewOpenAIWithOptions uses functional options
	g, err := NewOpenAIWithOptions(
		WithModel("gpt-4"),
		WithAPIKey("sk-test-options"),
		WithMaxTokens(2048),
		WithBaseURL(server.URL),
	)
	require.NoError(t, err)
	assert.Equal(t, "gpt-4", g.model)
	assert.Equal(t, 2048, g.maxTokens)
}

package nvcf

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

// mockNVCFChatResponse creates a mock NVCF chat completion response.
func mockNVCFChatResponse(content string, n int) map[string]any {
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
		"id":      "resp-nvcf-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "test-model",
		"choices": choices,
	}
}

// mockNVCFCompletionResponse creates a mock NVCF completion response.
func mockNVCFCompletionResponse(content string, n int) map[string]any {
	choices := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		choices[i] = map[string]any{
			"index":         i,
			"text":          content,
			"finish_reason": "stop",
		}
	}
	return map[string]any{
		"id":      "resp-nvcf-test",
		"object":  "text_completion",
		"created": 1234567890,
		"model":   "test-model",
		"choices": choices,
	}
}

func TestNvcfChat_RequiresFunctionID(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("response", 1))
	}))
	defer server.Close()

	// Should error without function_id
	_, err := NewNvcfChat(registry.Config{
		"api_key": "test-key",
	})
	assert.Error(t, err, "should require function_id")
	assert.Contains(t, err.Error(), "function_id")
}

func TestNvcfChat_RequiresAPIKey(t *testing.T) {
	// Clear any env var that might be set
	origKey := os.Getenv("NVCF_API_KEY")
	os.Unsetenv("NVCF_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("NVCF_API_KEY", origKey)
		}
	}()

	// Should error without API key
	_, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestNvcfChat_APIKeyFromEnv(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("response", 1))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("NVCF_API_KEY")
	os.Setenv("NVCF_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("NVCF_API_KEY", origKey)
		} else {
			os.Unsetenv("NVCF_API_KEY")
		}
	}()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestNvcfChat_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nvcf.NvcfChat", g.Name())
}

func TestNvcfChat_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "NVCF")
}

func TestNvcfChat_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify endpoint contains function ID
		assert.True(t, strings.Contains(r.URL.Path, "test-function-id"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Hello from NVCF!", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from NVCF!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestNvcfChat_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
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

func TestNvcfChat_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
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

func TestNvcfChat_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
		"max_tokens":  100,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Equal(t, float64(100), receivedRequest["max_tokens"])
}

func TestNvcfChat_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfChat(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
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

func TestNvcfChat_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("nvcf.NvcfChat")
	assert.True(t, ok, "nvcf.NvcfChat should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFChatResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nvcf.NvcfChat", g.Name())
}

// ========== NvcfCompletion Tests ==========

func TestNvcfCompletion_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFCompletionResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfCompletion(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nvcf.NvcfCompletion", g.Name())
}

func TestNvcfCompletion_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFCompletionResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNvcfCompletion(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "NVCF")
	assert.Contains(t, desc, "Completion")
}

func TestNvcfCompletion_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNVCFCompletionResponse("Completed text!", 1))
	}))
	defer server.Close()

	g, err := NewNvcfCompletion(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Complete this:")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Completed text!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format - should have "prompt" not "messages"
	prompt, ok := receivedRequest["prompt"].(string)
	assert.True(t, ok, "should have prompt field")
	assert.Equal(t, "Complete this:", prompt)

	// Should NOT have messages array
	_, hasMessages := receivedRequest["messages"]
	assert.False(t, hasMessages, "completion should not have messages array")
}

func TestNvcfCompletion_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("nvcf.NvcfCompletion")
	assert.True(t, ok, "nvcf.NvcfCompletion should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNVCFCompletionResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"function_id": "test-function-id",
		"api_key":     "test-key",
		"base_url":    server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nvcf.NvcfCompletion", g.Name())
}

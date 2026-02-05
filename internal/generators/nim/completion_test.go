package nim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNIMCompletionResponse creates a mock NIM completion response (OpenAI-compatible format).
func mockNIMCompletionResponse(content string, n int) map[string]any {
	choices := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		choices[i] = map[string]any{
			"index":         i,
			"text":          content,
			"finish_reason": "stop",
		}
	}
	return map[string]any{
		"id":      "cmpl-nim-test",
		"object":  "text_completion",
		"created": 1234567890,
		"model":   "meta/llama-2-70b",
		"choices": choices,
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestNVOpenAICompletion_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNVOpenAICompletion(registry.Config{
		"model":    "meta/llama-2-70b",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nim.NVOpenAICompletion", g.Name())
}

func TestNVOpenAICompletion_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNVOpenAICompletion(registry.Config{
		"model":    "meta/llama-2-70b",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "completion")
}

func TestNVOpenAICompletion_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify completions endpoint (not chat)
		assert.True(t, strings.Contains(r.URL.Path, "completions"))
		assert.False(t, strings.Contains(r.URL.Path, "chat/completions"))

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("Hello from NIM!", 1))
	}))
	defer server.Close()

	g, err := NewNVOpenAICompletion(registry.Config{
		"model":    "meta/llama-2-70b",
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

	// Verify request has prompt field (not messages)
	_, hasMessages := receivedRequest["messages"]
	_, hasPrompt := receivedRequest["prompt"]
	assert.False(t, hasMessages, "completions endpoint should not have messages")
	assert.True(t, hasPrompt, "completions endpoint should have prompt")
}

func TestNVOpenAICompletion_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("Response", n))
	}))
	defer server.Close()

	g, err := NewNVOpenAICompletion(registry.Config{
		"model":    "meta/llama-2-70b",
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

func TestNVOpenAICompletion_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("nim.NVOpenAICompletion")
	assert.True(t, ok, "nim.NVOpenAICompletion should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "meta/llama-2-70b",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nim.NVOpenAICompletion", g.Name())
}

func TestNVOpenAICompletion_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMCompletionResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewNVOpenAICompletion(registry.Config{
		"model":    "meta/llama-2-70b",
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

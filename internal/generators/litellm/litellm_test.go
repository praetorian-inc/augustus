package litellm

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

// mockLiteLLMResponse creates a mock OpenAI-format response.
func mockLiteLLMResponse(content string, n int) map[string]any {
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
		"model":   "anthropic/claude-3-opus",
		"choices": choices,
	}
}

func TestLiteLLM_RequiresProxyURL(t *testing.T) {
	_, err := NewLiteLLM(registry.Config{
		"model": "anthropic/claude-3-opus",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy_url")
}

func TestLiteLLM_RequiresModel(t *testing.T) {
	_, err := NewLiteLLM(registry.Config{
		"proxy_url": "http://localhost:4000",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestLiteLLM_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "anthropic/claude-3-opus",
	})
	require.NoError(t, err)
	assert.Equal(t, "litellm.LiteLLM", g.Name())
}

func TestLiteLLM_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "gpt-4",
	})
	require.NoError(t, err)
	assert.Contains(t, g.Description(), "LiteLLM")
}

func TestLiteLLM_Generate_SingleResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "chat/completions")
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("Hello from LiteLLM!", 1))
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "anthropic/claude-3-opus",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from LiteLLM!", responses[0].Content)
}

func TestLiteLLM_Generate_MultipleResponses_Supported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		n := 1
		if nVal, ok := req["n"].(float64); ok {
			n = int(nVal)
		}
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("Response", n))
	}))
	defer server.Close()

	// gpt-4 supports n parameter
	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "gpt-4",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	assert.Len(t, responses, 3)
}

func TestLiteLLM_Generate_MultipleResponses_Unsupported(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("Response", 1))
	}))
	defer server.Close()

	// anthropic/claude doesn't support n parameter - should make multiple calls
	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "anthropic/claude-3-opus",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	assert.Len(t, responses, 3)
	assert.Equal(t, 3, callCount, "Should make 3 separate API calls for unsupported n param")
}

func TestLiteLLM_Generate_SuppressedParams(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url":         server.URL,
		"model":             "anthropic/claude-3",
		"presence_penalty":  0.5,
		"suppressed_params": []any{"presence_penalty"},
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// presence_penalty should be suppressed
	_, hasPresencePenalty := receivedRequest["presence_penalty"]
	assert.False(t, hasPresencePenalty, "presence_penalty should be suppressed")
}

func TestLiteLLM_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Rate limit exceeded",
			},
		})
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "gpt-4",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "rate")
}

func TestLiteLLM_Registration(t *testing.T) {
	_, ok := generators.Get("litellm.LiteLLM")
	assert.True(t, ok, "litellm.LiteLLM should be registered")
}

func TestLiteLLM_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLiteLLMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": server.URL,
		"model":     "gpt-4",
	})
	require.NoError(t, err)

	// ClearHistory should not panic
	g.ClearHistory()
}

func TestLiteLLM_Integration(t *testing.T) {
	// Skip unless LITELLM_INTEGRATION_TEST is set
	if os.Getenv("LITELLM_INTEGRATION_TEST") == "" {
		t.Skip("Set LITELLM_INTEGRATION_TEST=1 to run integration tests")
	}

	proxyURL := os.Getenv("LITELLM_PROXY_URL")
	if proxyURL == "" {
		proxyURL = "http://localhost:4000"
	}

	model := os.Getenv("LITELLM_MODEL")
	if model == "" {
		model = "gpt-3.5-turbo" // Default to a common model
	}

	g, err := NewLiteLLM(registry.Config{
		"proxy_url": proxyURL,
		"model":     model,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Say 'hello' and nothing else.")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	t.Logf("Response: %s", responses[0].Content)
	assert.NotEmpty(t, responses[0].Content)
}

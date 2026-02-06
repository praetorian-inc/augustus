// Package huggingface provides generators using HuggingFace Inference API.
package huggingface

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

// mockHFResponse creates a mock HuggingFace Inference API response.
func mockHFResponse(texts []string) []map[string]any {
	responses := make([]map[string]any, len(texts))
	for i, text := range texts {
		responses[i] = map[string]any{
			"generated_text": text,
		}
	}
	return responses
}

func TestInferenceAPI_RequiresModel(t *testing.T) {
	_, err := NewInferenceAPI(registry.Config{
		"api_key": "test-key",
	})

	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestInferenceAPI_AcceptsAPIKeyFromConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-config-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-config-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestInferenceAPI_AcceptsAPIKeyFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("HF_INFERENCE_TOKEN")
	os.Setenv("HF_INFERENCE_TOKEN", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("HF_INFERENCE_TOKEN", origKey)
		} else {
			os.Unsetenv("HF_INFERENCE_TOKEN")
		}
	}()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestInferenceAPI_AcceptsAPIKeyFromAltEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-alt-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	// Set alternative env var
	origKey := os.Getenv("HUGGINGFACE_API_KEY")
	origHFKey := os.Getenv("HF_INFERENCE_TOKEN")
	os.Unsetenv("HF_INFERENCE_TOKEN")
	os.Setenv("HUGGINGFACE_API_KEY", "test-alt-key")
	defer func() {
		if origKey != "" {
			os.Setenv("HUGGINGFACE_API_KEY", origKey)
		} else {
			os.Unsetenv("HUGGINGFACE_API_KEY")
		}
		if origHFKey != "" {
			os.Setenv("HF_INFERENCE_TOKEN", origHFKey)
		}
	}()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestInferenceAPI_WorksWithoutAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No auth header expected
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	// Clear env vars
	origHFKey := os.Getenv("HF_INFERENCE_TOKEN")
	origAltKey := os.Getenv("HUGGINGFACE_API_KEY")
	os.Unsetenv("HF_INFERENCE_TOKEN")
	os.Unsetenv("HUGGINGFACE_API_KEY")
	defer func() {
		if origHFKey != "" {
			os.Setenv("HF_INFERENCE_TOKEN", origHFKey)
		}
		if origAltKey != "" {
			os.Setenv("HUGGINGFACE_API_KEY", origAltKey)
		}
	}()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestInferenceAPI_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "huggingface.InferenceAPI", g.Name())
}

func TestInferenceAPI_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "HuggingFace")
}

func TestInferenceAPI_Generate_SingleResponse(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"Hello from HuggingFace!"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from HuggingFace!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestInferenceAPI_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		params, _ := req["parameters"].(map[string]any)
		numSeq := 1
		if n, ok := params["num_return_sequences"].(float64); ok {
			numSeq = int(n)
		}

		texts := make([]string, numSeq)
		for i := 0; i < numSeq; i++ {
			texts[i] = "Response"
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse(texts))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	assert.Len(t, responses, 3)
	for _, resp := range responses {
		assert.Equal(t, "Response", resp.Content)
	}
}

func TestInferenceAPI_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":      "test-model",
		"api_key":    "test-key",
		"base_url":   server.URL,
		"max_tokens": 100,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, float64(100), params["max_new_tokens"])
}

func TestInferenceAPI_Generate_MaxTime(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
		"max_time": 30,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, float64(30), params["max_time"])
}

func TestInferenceAPI_Generate_DeprefixPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	// Test with deprefix_prompt=true (default)
	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, false, params["return_full_text"])
}

func TestInferenceAPI_Generate_DeprefixPromptFalse(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":           "test-model",
		"api_key":         "test-key",
		"base_url":        server.URL,
		"deprefix_prompt": false,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, true, params["return_full_text"])
}

func TestInferenceAPI_Generate_WaitForModel(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":          "test-model",
		"api_key":        "test-key",
		"base_url":       server.URL,
		"wait_for_model": true,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options := receivedRequest["options"].(map[string]any)
	assert.Equal(t, true, options["wait_for_model"])
}

func TestInferenceAPI_Generate_ModelLoading503(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call returns 503 (model loading)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":          "Model is loading",
				"estimated_time": 20.0,
			})
			return
		}
		// Second call succeeds
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, 2, callCount, "should retry on 503")
}

func TestInferenceAPI_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Rate limit exceeded",
		})
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
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

func TestInferenceAPI_Generate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Internal server error",
		})
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestInferenceAPI_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
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

func TestInferenceAPI_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	// Should not panic
	g.ClearHistory()

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
	assert.Len(t, responses, 1)
}

func TestInferenceAPI_Registration(t *testing.T) {
	factory, ok := generators.Get("huggingface.InferenceAPI")
	assert.True(t, ok, "huggingface.InferenceAPI should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "huggingface.InferenceAPI", g.Name())
}

func TestInferenceAPI_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
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

func TestInferenceAPI_MessagesFormat(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "test-model",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are helpful")
	conv.AddTurn(attempt.NewTurn("Hello").WithResponse("Hi there"))
	conv.AddPrompt("How are you?")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok, "should have messages array")
	// Should have: system + user + assistant + user = 4 messages
	assert.Len(t, messages, 4)
}

func TestInferenceAPI_BuildsCorrectURL(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(mockHFResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewInferenceAPI(registry.Config{
		"model":    "gpt2",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Contains(t, receivedPath, "gpt2", "URL should contain model name")
}

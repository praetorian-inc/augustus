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

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLLaVAResponse creates a mock HuggingFace LLaVA API response.
func mockLLaVAResponse(texts []string) []map[string]any {
	responses := make([]map[string]any, len(texts))
	for i, text := range texts {
		responses[i] = map[string]any{
			"generated_text": text,
		}
	}
	return responses
}

func TestLLaVA_RequiresModel(t *testing.T) {
	_, err := NewLLaVA(registry.Config{
		"api_key": "test-key",
	})

	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestLLaVA_AcceptsAPIKeyFromConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-config-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"I see a cat"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":  "test-config-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("What's in this image?")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestLLaVA_AcceptsAPIKeyFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-env-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
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

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestLLaVA_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "huggingface.LLaVA", g.Name())
}

func TestLLaVA_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, strings.ToLower(desc), "llava")
	assert.Contains(t, strings.ToLower(desc), "vision")
}

func TestLLaVA_Generate_WithImage(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"I see a cat in the image"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("What's in this image?")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "I see a cat in the image", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestLLaVA_Generate_MaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":      "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":    "test-key",
		"base_url":   server.URL,
		"max_tokens": 500,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify max_tokens was sent in request
	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, float64(500), params["max_new_tokens"])
}

func TestLLaVA_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Rate limit exceeded",
		})
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
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

func TestLLaVA_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
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

func TestLLaVA_Registration(t *testing.T) {
	factory, ok := generators.Get("huggingface.LLaVA")
	assert.True(t, ok, "huggingface.LLaVA should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "huggingface.LLaVA", g.Name())
}

func TestLLaVA_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockLLaVAResponse([]string{"response"}))
	}))
	defer server.Close()

	g, err := NewLLaVA(registry.Config{
		"model":    "llava-hf/llava-v1.6-mistral-7b-hf",
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

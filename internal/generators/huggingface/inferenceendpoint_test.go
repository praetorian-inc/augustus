// Package huggingface provides generators using HuggingFace Inference Endpoints.
package huggingface

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInferenceEndpoint_RequiresEndpointURL(t *testing.T) {
	_, err := NewInferenceEndpoint(registry.Config{
		"api_key": "test-key",
	})

	assert.Error(t, err, "should require endpoint_url")
	assert.Contains(t, err.Error(), "endpoint_url")
}

func TestNewInferenceEndpoint_AcceptsEndpointURL(t *testing.T) {
	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": "https://test.aws.endpoints.huggingface.cloud",
		"api_key":      "test-key",
	})

	require.NoError(t, err)
	assert.NotNil(t, g)
}

func TestInferenceEndpoint_Name(t *testing.T) {
	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": "https://test.aws.endpoints.huggingface.cloud",
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	assert.Equal(t, "huggingface.InferenceEndpoint", g.Name())
}

func TestInferenceEndpoint_Description(t *testing.T) {
	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": "https://test.aws.endpoints.huggingface.cloud",
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Inference Endpoint")
}

func TestInferenceEndpoint_Generate_SingleResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"generated_text": "Hello from custom endpoint!"},
		})
	}))
	defer server.Close()

	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": server.URL,
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from custom endpoint!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestInferenceEndpoint_Generate_UsesCustomURL(t *testing.T) {
	var receivedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"generated_text": "response"},
		})
	}))
	defer server.Close()

	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": server.URL,
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Endpoint URL should be used directly (no model suffix like InferenceAPI)
	assert.Equal(t, "/", receivedURL, "should POST to endpoint URL directly")
}

func TestInferenceEndpoint_AcceptsAPIKeyFromConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-endpoint-key", auth)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"generated_text": "response"},
		})
	}))
	defer server.Close()

	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": server.URL,
		"api_key":      "test-endpoint-key",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestInferenceEndpoint_AcceptsMaxTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"generated_text": "response"},
		})
	}))
	defer server.Close()

	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": server.URL,
		"api_key":      "test-key",
		"max_tokens":   200,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	params := receivedRequest["parameters"].(map[string]any)
	assert.Equal(t, float64(200), params["max_new_tokens"])
}

func TestInferenceEndpoint_ClearHistory(t *testing.T) {
	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": "https://test.aws.endpoints.huggingface.cloud",
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	// Should not panic
	g.ClearHistory()
}

func TestInferenceEndpoint_Registration(t *testing.T) {
	factory, ok := generators.Get("huggingface.InferenceEndpoint")
	assert.True(t, ok, "huggingface.InferenceEndpoint should be registered")

	if !ok {
		return
	}

	g, err := factory(registry.Config{
		"endpoint_url": "https://test.aws.endpoints.huggingface.cloud",
		"api_key":      "test-key",
	})
	require.NoError(t, err)
	assert.Equal(t, "huggingface.InferenceEndpoint", g.Name())
}

func TestInferenceEndpoint_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Endpoint is inactive",
		})
	}))
	defer server.Close()

	g, err := NewInferenceEndpoint(registry.Config{
		"endpoint_url": server.URL,
		"api_key":      "test-key",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")
}

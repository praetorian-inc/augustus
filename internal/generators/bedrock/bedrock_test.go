package bedrock

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

// mockBedrockResponse creates a mock Bedrock InvokeModel response.
// Bedrock returns responses in the model-specific format.
func mockBedrockClaudeResponse(content string) map[string]any {
	return map[string]any{
		"type": "message",
		"role": "assistant",
		"content": []map[string]any{
			{
				"type": "text",
				"text": content,
			},
		},
		"stop_reason": "end_turn",
		"usage": map[string]any{
			"input_tokens":  10,
			"output_tokens": 20,
		},
	}
}

func TestBedrockGenerator_RequiresModel(t *testing.T) {
	// Should error without model ID
	_, err := NewBedrock(registry.Config{
		"region": "us-east-1",
	})
	assert.Error(t, err, "should require model ID")
	assert.Contains(t, err.Error(), "model")
}

func TestBedrockGenerator_RequiresRegion(t *testing.T) {
	// Should error without region
	_, err := NewBedrock(registry.Config{
		"model": "anthropic.claude-3-sonnet-20240229-v1:0",
	})
	assert.Error(t, err, "should require region")
	assert.Contains(t, err.Error(), "region")
}

func TestBedrockGenerator_SupportsClaudeModels(t *testing.T) {
	claudeModels := []string{
		"anthropic.claude-3-opus-20240229-v1:0",
		"anthropic.claude-3-sonnet-20240229-v1:0",
		"anthropic.claude-3-haiku-20240307-v1:0",
		"anthropic.claude-v2",
		"anthropic.claude-v2:1",
	}

	for _, modelID := range claudeModels {
		t.Run(modelID, func(t *testing.T) {
			g, err := NewBedrock(registry.Config{
				"model":  modelID,
				"region": "us-east-1",
			})
			require.NoError(t, err)
			assert.NotNil(t, g)
			assert.Contains(t, g.Name(), "bedrock")
		})
	}
}

func TestBedrockGenerator_Generate(t *testing.T) {
	// Create a mock HTTP server that simulates Bedrock API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a POST to /model/{modelId}/invoke
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/invoke")

		// Return mock response
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockClaudeResponse("Hello from Bedrock!"))
	}))
	defer server.Close()

	// Create generator with custom endpoint (pointing to mock server)
	g, err := NewBedrock(registry.Config{
		"model":    "anthropic.claude-3-sonnet-20240229-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	// Create a simple conversation
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	// Generate response
	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "Hello from Bedrock!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

func TestBedrockGenerator_GenerateMultiple(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockClaudeResponse("Response " + string(rune('0'+callCount))))
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "anthropic.claude-3-sonnet-20240229-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	// Request 3 generations
	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	require.Len(t, responses, 3)
	assert.Equal(t, 3, callCount, "should make 3 API calls")
}

func TestBedrockGenerator_HandlesRateLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "ThrottlingException: Rate exceeded",
		})
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "anthropic.claude-3-sonnet-20240229-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit")
}

func TestBedrockGenerator_HandlesAuthErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "AccessDeniedException: Insufficient permissions",
		})
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "anthropic.claude-3-sonnet-20240229-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestBedrockGenerator_Name(t *testing.T) {
	g, err := NewBedrock(registry.Config{
		"model":  "anthropic.claude-3-sonnet-20240229-v1:0",
		"region": "us-east-1",
	})
	require.NoError(t, err)

	name := g.Name()
	assert.Contains(t, name, "bedrock")
	assert.NotEmpty(t, name)
}

func TestBedrockGenerator_Description(t *testing.T) {
	g, err := NewBedrock(registry.Config{
		"model":  "anthropic.claude-3-sonnet-20240229-v1:0",
		"region": "us-east-1",
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.Contains(t, desc, "Bedrock")
	assert.NotEmpty(t, desc)
}

func TestBedrockGenerator_ClearHistory(t *testing.T) {
	g, err := NewBedrock(registry.Config{
		"model":  "anthropic.claude-3-sonnet-20240229-v1:0",
		"region": "us-east-1",
	})
	require.NoError(t, err)

	// Should not panic
	g.ClearHistory()
}

func TestBedrockGenerator_RegistersWithRegistry(t *testing.T) {
	// Verify the generator registered itself
	names := generators.List()
	found := false
	for _, name := range names {
		if name == "bedrock.Bedrock" {
			found = true
			break
		}
	}
	assert.True(t, found, "bedrock generator should be registered")
}

func TestBedrockGenerator_AWSCredentials(t *testing.T) {
	// Test that it uses AWS credentials from environment or default locations
	// This is a basic test that the generator can be created without explicit credentials
	t.Skip("Skipping AWS credentials test - requires AWS configuration")

	g, err := NewBedrock(registry.Config{
		"model":  "anthropic.claude-3-sonnet-20240229-v1:0",
		"region": "us-east-1",
	})
	require.NoError(t, err)
	assert.NotNil(t, g)
}

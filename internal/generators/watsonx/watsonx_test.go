package watsonx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWatsonXTextGenResponse creates a mock Watson X text generation response.
func mockWatsonXTextGenResponse(content string) map[string]any {
	return map[string]any{
		"model_id":     "ibm/granite-13b-chat-v2",
		"model_version": "1.0.0",
		"created_at":    "2024-01-01T00:00:00.000Z",
		"results": []map[string]any{
			{
				"generated_text": content,
				"generated_token_count": 50,
				"input_token_count": 10,
				"stop_reason": "eos_token",
			},
		},
	}
}

// mockWatsonXDeploymentResponse creates a mock Watson X deployment response.
func mockWatsonXDeploymentResponse(content string) map[string]any {
	return map[string]any{
		"predictions": []map[string]any{
			{
				"values": []string{content},
			},
		},
	}
}

func TestWatsonXGenerator_RequiresAPIKey(t *testing.T) {
	// Should error without API key
	_, err := NewWatsonX(registry.Config{
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
		"region": "us-south",
	})
	assert.Error(t, err, "should require API key")
	assert.Contains(t, err.Error(), "api_key")
}

func TestWatsonXGenerator_RequiresProjectIDOrDeploymentID(t *testing.T) {
	// Should error without project_id or deployment_id
	_, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"model": "ibm/granite-13b-chat-v2",
		"region": "us-south",
	})
	assert.Error(t, err, "should require project_id or deployment_id")
	assert.Contains(t, err.Error(), "project_id")
}

func TestWatsonXGenerator_RequiresModel(t *testing.T) {
	// Should error without model
	_, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"project_id": "test-project",
		"region": "us-south",
	})
	assert.Error(t, err, "should require model")
	assert.Contains(t, err.Error(), "model")
}

func TestWatsonXGenerator_RequiresRegion(t *testing.T) {
	// Should error without region
	_, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
	})
	assert.Error(t, err, "should require region")
	assert.Contains(t, err.Error(), "region")
}

func TestWatsonXGenerator_GenerateWithProjectID(t *testing.T) {
	// Create mock Watson X server
	var requestBody map[string]any
	var requestHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture request for verification
		requestHeaders = r.Header
		_ = json.NewDecoder(r.Body).Decode(&requestBody)

		// Mock IAM token endpoint
		if strings.Contains(r.URL.Path, "/identity/token") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-bearer-token",
				"expires_in": 3600,
			})
			return
		}

		// Mock text generation endpoint
		if strings.Contains(r.URL.Path, "/ml/v1/text/generation") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockWatsonXTextGenResponse("Hello from Watson X!"))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create generator with project_id
	gen, err := NewWatsonX(registry.Config{
		"api_key": "test-api-key",
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project-id",
		"region": "us-south",
		"url": server.URL,
		"iam_url": server.URL + "/identity/token",
	})
	require.NoError(t, err)

	// Generate response
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Watson X!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request
	assert.Equal(t, "Hello", requestBody["input"])
	assert.Equal(t, "test-project-id", requestBody["project_id"])
	assert.Equal(t, "ibm/granite-13b-chat-v2", requestBody["model_id"])
	assert.Contains(t, requestHeaders.Get("Authorization"), "Bearer")
}

func TestWatsonXGenerator_GenerateWithDeploymentID(t *testing.T) {
	// Create mock Watson X server
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock IAM token endpoint
		if strings.Contains(r.URL.Path, "/identity/token") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-bearer-token",
				"expires_in": 3600,
			})
			return
		}

		// Mock deployment generation endpoint
		if strings.Contains(r.URL.Path, "/ml/v1/deployments/") {
			_ = json.NewDecoder(r.Body).Decode(&requestBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockWatsonXTextGenResponse("Deployed response"))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create generator with deployment_id
	gen, err := NewWatsonX(registry.Config{
		"api_key": "test-api-key",
		"model": "ibm/granite-13b-chat-v2",
		"deployment_id": "test-deployment-id",
		"region": "us-south",
		"url": server.URL,
		"iam_url": server.URL + "/identity/token",
	})
	require.NoError(t, err)

	// Generate response
	conv := attempt.NewConversation()
	conv.AddPrompt("Test prompt")

	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "Deployed response", responses[0].Content)
}

func TestWatsonXGenerator_GenerateMultiple(t *testing.T) {
	// Watson X doesn't support multiple completions in single call
	// So we make multiple API calls
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/token") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-bearer-token",
			})
			return
		}

		if strings.Contains(r.URL.Path, "/ml/v1/text/generation") {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockWatsonXTextGenResponse("Response " + string(rune('0'+callCount))))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	gen, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
		"region": "us-south",
		"url": server.URL,
		"iam_url": server.URL + "/identity/token",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test")

	// Request 3 completions
	responses, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	assert.Len(t, responses, 3)
	assert.Equal(t, 3, callCount, "should make 3 API calls")
}

func TestWatsonXGenerator_Name(t *testing.T) {
	gen := &WatsonX{}
	assert.Equal(t, "watsonx.WatsonX", gen.Name())
}

func TestWatsonXGenerator_Description(t *testing.T) {
	gen := &WatsonX{}
	assert.Contains(t, gen.Description(), "IBM Watson X")
}

func TestWatsonXGenerator_ClearHistory(t *testing.T) {
	gen := &WatsonX{}
	// Should not panic (no-op is valid)
	gen.ClearHistory()
}

func TestWatsonXGenerator_EmptyPromptHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token"})
			return
		}

		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		// Should receive null byte for empty prompt
		if input, ok := body["input"].(string); ok {
			assert.Equal(t, "\x00", input, "empty prompt should become null byte")
		}

		_ = json.NewEncoder(w).Encode(mockWatsonXTextGenResponse("response"))
	}))
	defer server.Close()

	gen, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
		"region": "us-south",
		"url": server.URL,
		"iam_url": server.URL + "/identity/token",
	})
	require.NoError(t, err)

	// Empty conversation
	conv := attempt.NewConversation()
	conv.AddPrompt("")

	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
}

func TestWatsonXGenerator_MaxTokensConfiguration(t *testing.T) {
	var requestBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "token"})
			return
		}

		if strings.Contains(r.URL.Path, "/ml/v1/text/generation") {
			_ = json.NewDecoder(r.Body).Decode(&requestBody)
			_ = json.NewEncoder(w).Encode(mockWatsonXTextGenResponse("response"))
			return
		}
	}))
	defer server.Close()

	gen, err := NewWatsonX(registry.Config{
		"api_key": "test-key",
		"model": "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
		"region": "us-south",
		"max_tokens": 500,
		"url": server.URL,
		"iam_url": server.URL + "/identity/token",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify max_tokens in request
	params := requestBody["parameters"].(map[string]any)
	assert.Equal(t, float64(500), params["max_new_tokens"])
}

package vertex

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

// mockVertexResponse creates a mock Vertex AI API response.
func mockVertexResponse(content string) map[string]any {
	return map[string]any{
		"candidates": []map[string]any{
			{
				"content": map[string]any{
					"parts": []map[string]any{
						{
							"text": content,
						},
					},
					"role": "model",
				},
				"finishReason": "STOP",
			},
		},
		"usageMetadata": map[string]any{
			"promptTokenCount":     10,
			"candidatesTokenCount": 20,
			"totalTokenCount":      30,
		},
	}
}

func TestVertexGenerator_RequiresModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	// Should error without model name
	_, err := NewVertex(registry.Config{
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestVertexGenerator_RequiresProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	// Should error without project_id
	_, err := NewVertex(registry.Config{
		"model":    "gemini-pro",
		"location": "us-central1",
		"base_url": server.URL,
	})
	assert.Error(t, err, "should require project_id")
	assert.Contains(t, err.Error(), "project_id")
}

func TestVertexGenerator_DefaultLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify URL contains location
		assert.Contains(t, r.URL.Path, "us-central1", "should use default location")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"base_url":   server.URL,
		// No location - should use default
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestVertexGenerator_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "vertex.Vertex", g.Name())
}

func TestVertexGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Vertex AI")
}

func TestVertexGenerator_Generate_SingleResponse(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)

		// Verify it's the generateContent endpoint
		assert.Contains(t, r.URL.Path, "generateContent")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Hello from Gemini!"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Gemini!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format - Vertex AI uses contents array
	contents, ok := receivedRequest["contents"].([]any)
	assert.True(t, ok, "should have contents array")
	assert.Len(t, contents, 1)
}

func TestVertexGenerator_Generate_MultipleResponses(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Generate multiple responses
	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	assert.Len(t, responses, 3)
	// Should have made 3 API calls
	assert.Equal(t, 3, callCount)
}

func TestVertexGenerator_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant.")
	conv.AddPrompt("Hello!")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Vertex AI uses systemInstruction parameter for system prompts
	systemInstruction, ok := receivedRequest["systemInstruction"].(map[string]any)
	require.True(t, ok, "should have systemInstruction parameter")
	parts, ok := systemInstruction["parts"].([]any)
	require.True(t, ok, "systemInstruction should have parts array")
	assert.Len(t, parts, 1)
}

func TestVertexGenerator_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":       "gemini-pro",
		"project_id":  "test-project",
		"location":    "us-central1",
		"base_url":    server.URL,
		"temperature": 0.5,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	generationConfig, ok := receivedRequest["generationConfig"].(map[string]any)
	require.True(t, ok, "should have generationConfig")
	assert.Equal(t, 0.5, generationConfig["temperature"])
}

func TestVertexGenerator_Generate_MaxOutputTokens(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":             "gemini-pro",
		"project_id":        "test-project",
		"location":          "us-central1",
		"base_url":          server.URL,
		"max_output_tokens": 256,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	generationConfig, ok := receivedRequest["generationConfig"].(map[string]any)
	require.True(t, ok, "should have generationConfig")
	assert.Equal(t, float64(256), generationConfig["maxOutputTokens"])
}

func TestVertexGenerator_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
		"top_p":      0.9,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	generationConfig, ok := receivedRequest["generationConfig"].(map[string]any)
	require.True(t, ok, "should have generationConfig")
	assert.Equal(t, 0.9, generationConfig["topP"])
}

func TestVertexGenerator_Generate_TopK(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
		"top_k":      40,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	generationConfig, ok := receivedRequest["generationConfig"].(map[string]any)
	require.True(t, ok, "should have generationConfig")
	assert.Equal(t, float64(40), generationConfig["topK"])
}

func TestVertexGenerator_SupportedModels(t *testing.T) {
	models := []string{
		"gemini-pro",
		"gemini-pro-vision",
		"text-bison",      // PaLM 2
		"chat-bison",      // PaLM 2
		"text-bison-32k",  // PaLM 2
		"chat-bison-32k",  // PaLM 2
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Contains(t, r.URL.Path, model)
				_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
			}))
			defer server.Close()

			g, err := NewVertex(registry.Config{
				"model":      model,
				"project_id": "test-project",
				"location":   "us-central1",
				"base_url":   server.URL,
			})
			require.NoError(t, err)

			conv := attempt.NewConversation()
			conv.AddPrompt("test")

			_, err = g.Generate(context.Background(), conv, 1)
			assert.NoError(t, err)
		})
	}
}

func TestVertexGenerator_Generate_RateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    429,
				"message": "Resource exhausted",
				"status":  "RESOURCE_EXHAUSTED",
			},
		})
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "rate")
}

func TestVertexGenerator_Generate_AuthenticationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    401,
				"message": "Unauthenticated",
				"status":  "UNAUTHENTICATED",
			},
		})
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "auth")
}

func TestVertexGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
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

func TestVertexGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("vertex.Vertex")
	assert.True(t, ok, "vertex.Vertex should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "vertex.Vertex", g.Name())
}

func TestVertexGenerator_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 0)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

func TestVertexGenerator_APIKeyFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Authorization header
		auth := r.Header.Get("Authorization")
		assert.Contains(t, auth, "Bearer test-env-key")

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	// Set env var
	origKey := os.Getenv("GOOGLE_API_KEY")
	os.Setenv("GOOGLE_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("GOOGLE_API_KEY", origKey)
		} else {
			os.Unsetenv("GOOGLE_API_KEY")
		}
	}()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

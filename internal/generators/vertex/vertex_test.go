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
	"github.com/praetorian-inc/augustus/pkg/probes"
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

// mockVertexFunctionCallResponse creates a mock Vertex AI API response containing
// a function call part instead of text.
func mockVertexFunctionCallResponse(name string, args map[string]any) map[string]any {
	return map[string]any{
		"candidates": []map[string]any{
			{
				"content": map[string]any{
					"parts": []map[string]any{
						{
							"functionCall": map[string]any{
								"name": name,
								"args": args,
							},
						},
					},
					"role": "model",
				},
				"finishReason": "STOP",
			},
		},
		"usageMetadata": map[string]any{
			"promptTokenCount":     10,
			"candidatesTokenCount": 5,
			"totalTokenCount":      15,
		},
	}
}

func TestVertexGenerator_Generate_WithTools(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("I will search"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety")
	conv.Tools = []map[string]any{
		{
			"name":        "web_search",
			"description": "Search the web",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
				},
			},
		},
	}

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Vertex AI wraps function declarations inside a tools array element
	tools, ok := receivedRequest["tools"].([]any)
	require.True(t, ok, "request must contain tools array")
	require.Len(t, tools, 1)

	toolDecl := tools[0].(map[string]any)
	funcDecls, ok := toolDecl["functionDeclarations"].([]any)
	require.True(t, ok, "tool must contain functionDeclarations array")
	require.Len(t, funcDecls, 1)

	fd := funcDecls[0].(map[string]any)
	assert.Equal(t, "web_search", fd["name"])
	assert.Equal(t, "Search the web", fd["description"])
	assert.NotNil(t, fd["parameters"])
}

func TestVertexGenerator_Generate_ToolChoiceAuto(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "auto"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	toolConfig, ok := receivedRequest["toolConfig"].(map[string]any)
	require.True(t, ok, "request must contain toolConfig")
	fcc, ok := toolConfig["functionCallingConfig"].(map[string]any)
	require.True(t, ok, "toolConfig must contain functionCallingConfig")
	assert.Equal(t, "AUTO", fcc["mode"])
}

func TestVertexGenerator_Generate_ToolChoiceRequired(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "required"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	toolConfig, ok := receivedRequest["toolConfig"].(map[string]any)
	require.True(t, ok, "request must contain toolConfig")
	fcc, ok := toolConfig["functionCallingConfig"].(map[string]any)
	require.True(t, ok, "toolConfig must contain functionCallingConfig")
	assert.Equal(t, "ANY", fcc["mode"])
}

func TestVertexGenerator_Generate_ToolChoiceByName(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("response"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "web_search"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	toolConfig, ok := receivedRequest["toolConfig"].(map[string]any)
	require.True(t, ok, "request must contain toolConfig")
	fcc, ok := toolConfig["functionCallingConfig"].(map[string]any)
	require.True(t, ok, "toolConfig must contain functionCallingConfig")
	assert.Equal(t, "ANY", fcc["mode"])

	allowed, ok := fcc["allowedFunctionNames"].([]any)
	require.True(t, ok, "functionCallingConfig must contain allowedFunctionNames")
	require.Len(t, allowed, 1)
	assert.Equal(t, "web_search", allowed[0])
}

func TestVertexGenerator_Generate_NoToolsOmitted(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Hello"))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	_, hasTools := receivedRequest["tools"]
	assert.False(t, hasTools, "request should not contain tools when none set on conversation")
}

func TestVertexGenerator_Generate_ResponseFunctionCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockVertexFunctionCallResponse(
			"web_search",
			map[string]any{"query": "AI safety"},
		))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"api_key":    "test-key",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	require.NotNil(t, responses[0].ToolCalls, "response should carry tool calls")
	require.Len(t, responses[0].ToolCalls, 1)
	assert.Equal(t, "web_search", responses[0].ToolCalls[0]["name"])
	args, ok := responses[0].ToolCalls[0]["args"].(map[string]any)
	require.True(t, ok, "tool call must have args map")
	assert.Equal(t, "AI safety", args["query"])
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
	_ = os.Setenv("GOOGLE_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			_ = os.Setenv("GOOGLE_API_KEY", origKey)
		} else {
			_ = os.Unsetenv("GOOGLE_API_KEY")
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

func TestVertexGenerator_Generate_ToolResultReplayJSON(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("The temperature is 72 degrees."))
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	// Build a two-turn conversation: user question + simulated model tool call + tool result.
	conv := attempt.NewConversation()
	conv.AddPrompt("What's the weather?")

	// First turn: simulate model's tool call response.
	assistantMsg := attempt.NewAssistantMessage("")
	assistantMsg.ToolCalls = []map[string]any{
		{"name": "get_weather", "args": map[string]any{"location": "SF"}},
	}
	conv.Turns[0].Response = &assistantMsg

	// Second turn: inject tool result with valid JSON content.
	toolResult := attempt.NewToolResultMessage("get_weather", `{"temperature": 72}`)
	conv.Turns = append(conv.Turns, attempt.Turn{Prompt: toolResult})

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify the request contains a "function" role content with the expected functionResponse.
	contents, ok := receivedRequest["contents"].([]any)
	require.True(t, ok, "request must contain contents array")

	// Find the function-role content block.
	var funcContent map[string]any
	for _, c := range contents {
		cb, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if cb["role"] == "function" {
			funcContent = cb
			break
		}
	}
	require.NotNil(t, funcContent, "contents must include a 'function' role entry for the tool result")

	parts, ok := funcContent["parts"].([]any)
	require.True(t, ok, "function content must have parts")
	require.Len(t, parts, 1)

	part, ok := parts[0].(map[string]any)
	require.True(t, ok)
	funcResp, ok := part["functionResponse"].(map[string]any)
	require.True(t, ok, "part must contain functionResponse")
	assert.Equal(t, "get_weather", funcResp["name"])

	response, ok := funcResp["response"].(map[string]any)
	require.True(t, ok, "functionResponse must have response map")
	assert.Equal(t, float64(72), response["temperature"])
}

func TestVertexGenerator_Generate_ToolResultReplayNonJSON(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockVertexResponse("Got it."))
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
	conv.AddPrompt("What's the weather?")

	assistantMsg := attempt.NewAssistantMessage("")
	assistantMsg.ToolCalls = []map[string]any{
		{"name": "get_weather", "args": map[string]any{"location": "SF"}},
	}
	conv.Turns[0].Response = &assistantMsg

	// Tool result with plain-text (non-JSON) content.
	toolResult := attempt.NewToolResultMessage("get_weather", "The temperature is 72 degrees")
	conv.Turns = append(conv.Turns, attempt.Turn{Prompt: toolResult})

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	contents, ok := receivedRequest["contents"].([]any)
	require.True(t, ok, "request must contain contents array")

	var funcContent map[string]any
	for _, c := range contents {
		cb, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if cb["role"] == "function" {
			funcContent = cb
			break
		}
	}
	require.NotNil(t, funcContent, "contents must include a 'function' role entry for the tool result")

	parts, ok := funcContent["parts"].([]any)
	require.True(t, ok)
	require.Len(t, parts, 1)

	part, ok := parts[0].(map[string]any)
	require.True(t, ok)
	funcResp, ok := part["functionResponse"].(map[string]any)
	require.True(t, ok, "part must contain functionResponse")
	assert.Equal(t, "get_weather", funcResp["name"])

	// Non-JSON content must be wrapped under "result".
	response, ok := funcResp["response"].(map[string]any)
	require.True(t, ok, "functionResponse must have response map")
	assert.Equal(t, "The temperature is 72 degrees", response["result"])
}

func TestVertexGenerator_Generate_ToolChoiceNone(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
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

	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	conv.Tools = []map[string]any{{"name": "web_search", "description": "Search"}}
	conv.ToolChoice = "none"

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// tools key must be absent when ToolChoice == "none".
	_, hasTools := receivedRequest["tools"]
	assert.False(t, hasTools, "tools key must be absent when ToolChoice is none")

	toolConfig, ok := receivedRequest["toolConfig"].(map[string]any)
	require.True(t, ok, "request must contain toolConfig")
	fcc, ok := toolConfig["functionCallingConfig"].(map[string]any)
	require.True(t, ok, "toolConfig must contain functionCallingConfig")
	assert.Equal(t, "NONE", fcc["mode"])
}

func TestVertexGenerator_Generate_InvalidToolNameError(t *testing.T) {
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

	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	conv.Tools = []map[string]any{{"name": "", "description": "Bad tool"}}

	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err, "empty tool name must return an error")
	assert.Contains(t, err.Error(), "missing valid string name")
}

// TestVertexGenerator_TwoTurnToolResult_NameMatchesFunctionCall tests the bug
// described in PR #131: when RunTwoTurnPrompts produces a tool-result turn using
// the "call_"+name fallback ID (because NormalizeGeminiFunctionCalls did not set
// an "id" field), conversationToContents must send the bare function name in
// functionResponse.Name, not the "call_web_search" fallback. Gemini requires
// functionResponse.name == functionCall.name.
//
// This test drives the real RunTwoTurnPrompts → Vertex serialization path to
// reproduce the mismatch.
func TestVertexGenerator_TwoTurnToolResult_NameMatchesFunctionCall(t *testing.T) {
	// turn1Server returns a functionCall response (no "id" field, matching Gemini wire format).
	// turn2Server captures the second request so we can assert functionResponse.name.
	var turn2Request map[string]any
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Turn 1: return a function call for "web_search"
			_ = json.NewEncoder(w).Encode(mockVertexFunctionCallResponse(
				"web_search",
				map[string]any{"query": "AI safety"},
			))
		} else {
			// Turn 2: capture the full request and return a text response
			_ = json.NewDecoder(r.Body).Decode(&turn2Request)
			_ = json.NewEncoder(w).Encode(mockVertexResponse("Here are the results."))
		}
	}))
	defer server.Close()

	g, err := NewVertex(registry.Config{
		"model":      "gemini-pro",
		"project_id": "test-project",
		"location":   "us-central1",
		"base_url":   server.URL,
	})
	require.NoError(t, err)

	// Drive through RunTwoTurnPrompts — this is the real production path
	// where NormalizeGeminiFunctionCalls builds tool-call entries without "id",
	// causing the fallback "call_"+name to flow into ToolCallID.
	_, err = probes.RunTwoTurnPrompts(
		context.Background(),
		g,
		[]string{"Search for AI safety"},
		"test-probe",
		"test-detector",
		[]map[string]any{{"name": "web_search", "description": "Search the web"}},
		"auto",
		map[string]string{"web_search": `{"results": ["result1"]}`},
	)
	require.NoError(t, err)

	// Verify that the second request was actually sent (Turn 2 fired).
	require.Equal(t, 2, callCount, "expected 2 API calls (turn1 + turn2)")
	require.NotNil(t, turn2Request, "turn 2 request must have been captured")

	// Extract the "function" role content from Turn 2's contents.
	contents, ok := turn2Request["contents"].([]any)
	require.True(t, ok, "turn2 request must contain contents array")

	var funcContent map[string]any
	for _, c := range contents {
		cb, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if cb["role"] == "function" {
			funcContent = cb
			break
		}
	}
	require.NotNil(t, funcContent, "turn2 contents must include a 'function' role entry")

	parts, ok := funcContent["parts"].([]any)
	require.True(t, ok, "function content must have parts")
	require.Len(t, parts, 1)

	part, ok := parts[0].(map[string]any)
	require.True(t, ok)
	funcResp, ok := part["functionResponse"].(map[string]any)
	require.True(t, ok, "part must contain functionResponse")

	// THE KEY ASSERTION: functionResponse.name must equal the bare function name
	// "web_search", NOT the fallback "call_web_search". Gemini rejects mismatches.
	assert.Equal(t, "web_search", funcResp["name"],
		"functionResponse.name must match functionCall.name (bare name), not the 'call_'+name fallback")
}

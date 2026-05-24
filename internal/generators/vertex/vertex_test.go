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

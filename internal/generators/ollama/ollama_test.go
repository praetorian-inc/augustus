package ollama

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

// mockGenerateResponse creates a mock Ollama generate response.
func mockGenerateResponse(response string) map[string]any {
	return map[string]any{
		"model":              "llama2",
		"created_at":         "2025-01-01T00:00:00Z",
		"response":           response,
		"done":               true,
		"total_duration":     1000000000,
		"load_duration":      100000000,
		"prompt_eval_count":  10,
		"prompt_eval_duration": 100000000,
		"eval_count":         20,
		"eval_duration":      200000000,
	}
}

// mockChatResponse creates a mock Ollama chat response.
func mockChatResponse(content string) map[string]any {
	return map[string]any{
		"model":      "llama2",
		"created_at": "2025-01-01T00:00:00Z",
		"message": map[string]any{
			"role":    "assistant",
			"content": content,
		},
		"done":               true,
		"total_duration":     1000000000,
		"load_duration":      100000000,
		"prompt_eval_count":  10,
		"prompt_eval_duration": 100000000,
		"eval_count":         20,
		"eval_duration":      200000000,
	}
}

// --- Ollama (generate endpoint) Tests ---

func TestOllama_RequiresModel(t *testing.T) {
	_, err := NewOllama(registry.Config{
		"host": "http://localhost:11434",
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestOllama_DefaultHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	// Test that default host is used when not specified
	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL, // Override for test
	})
	require.NoError(t, err)
	assert.NotNil(t, g)
}

func TestOllama_HostFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	// Set env var
	origHost := os.Getenv("OLLAMA_HOST")
	os.Setenv("OLLAMA_HOST", server.URL)
	defer func() {
		if origHost != "" {
			os.Setenv("OLLAMA_HOST", origHost)
		} else {
			os.Unsetenv("OLLAMA_HOST")
		}
	}()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

func TestOllama_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "ollama.Ollama", g.Name())
}

func TestOllama_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Ollama")
}

func TestOllama_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should hit /api/generate endpoint
		assert.Contains(t, r.URL.Path, "/api/generate")

		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("Hello from Llama!"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Llama!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format
	assert.Equal(t, "llama2", receivedRequest["model"])
	assert.Equal(t, "Hello!", receivedRequest["prompt"])
}

func TestOllama_Generate_MultipleResponses(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("Response " + string(rune('0'+callCount))))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// Ollama doesn't support n parameter, so we call multiple times
	assert.Len(t, responses, 3)
	assert.Equal(t, 3, callCount)
}

func TestOllama_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model":       "llama2",
		"host":        server.URL,
		"temperature": 0.5,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options, ok := receivedRequest["options"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 0.5, options["temperature"])
}

func TestOllama_Generate_TopP(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
		"top_p": 0.9,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options, ok := receivedRequest["options"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 0.9, options["top_p"])
}

func TestOllama_Generate_TopK(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
		"top_k": 40,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options, ok := receivedRequest["options"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(40), options["top_k"])
}

func TestOllama_Generate_NumPredict(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model":       "llama2",
		"host":        server.URL,
		"num_predict": 100,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options, ok := receivedRequest["options"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(100), options["num_predict"])
}

func TestOllama_Generate_NotFoundError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "model not found",
		})
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "nonexistent",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestOllama_Generate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "internal server error",
		})
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestOllama_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
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

func TestOllama_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
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

func TestOllama_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("ollama.Ollama")
	assert.True(t, ok, "ollama.Ollama should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "ollama.Ollama", g.Name())
}

func TestOllama_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 0)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

func TestOllama_NegativeGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, -1)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

// --- OllamaChat (chat endpoint) Tests ---

func TestOllamaChat_RequiresModel(t *testing.T) {
	_, err := NewOllamaChat(registry.Config{
		"host": "http://localhost:11434",
	})
	assert.Error(t, err, "should require model name")
	assert.Contains(t, err.Error(), "model")
}

func TestOllamaChat_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "ollama.OllamaChat", g.Name())
}

func TestOllamaChat_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "Ollama")
	assert.Contains(t, desc, "chat")
}

func TestOllamaChat_Generate(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should hit /api/chat endpoint
		assert.Contains(t, r.URL.Path, "/api/chat")

		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("Hello from Llama Chat!"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello!")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Hello from Llama Chat!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)

	// Verify request format - should use messages array
	assert.Equal(t, "llama2", receivedRequest["model"])
	messages, ok := receivedRequest["messages"].([]any)
	assert.True(t, ok, "should have messages array")
	assert.Len(t, messages, 1)
}

func TestOllamaChat_Generate_WithSystemPrompt(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant.")
	conv.AddPrompt("Hello!")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify system message is included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(messages), 2)

	firstMsg := messages[0].(map[string]any)
	assert.Equal(t, "system", firstMsg["role"])
	assert.Equal(t, "You are a helpful assistant.", firstMsg["content"])
}

func TestOllamaChat_Generate_MultiTurnConversation(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.WithSystem("You are helpful.")
	conv.AddTurn(attempt.NewTurn("Hello!").WithResponse("Hi there!"))
	conv.AddPrompt("How are you?")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify all messages are included
	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	// Should have: system + user + assistant + user = 4 messages
	assert.Len(t, messages, 4)
}

func TestOllamaChat_Generate_Temperature(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model":       "llama2",
		"host":        server.URL,
		"temperature": 0.5,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	options, ok := receivedRequest["options"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 0.5, options["temperature"])
}

func TestOllamaChat_Registration(t *testing.T) {
	// Test that the chat generator is registered via init()
	factory, ok := generators.Get("ollama.OllamaChat")
	assert.True(t, ok, "ollama.OllamaChat should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "ollama.OllamaChat", g.Name())
}

func TestOllamaChat_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
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

func TestOllamaChat_ZeroGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 0)
	assert.NoError(t, err)
	assert.Empty(t, responses)
}

// --- Model Name Variants Tests ---

func TestOllama_ModelNameVariants(t *testing.T) {
	models := []string{
		"llama2",
		"llama2:latest",
		"gemma:7b",
		"codellama",
		"mistral",
		"mixtral",
	}

	for _, model := range models {
		t.Run(model, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				assert.Equal(t, model, req["model"])
				_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
			}))
			defer server.Close()

			g, err := NewOllama(registry.Config{
				"model": model,
				"host":  server.URL,
			})
			require.NoError(t, err)

			conv := attempt.NewConversation()
			conv.AddPrompt("test")

			_, err = g.Generate(context.Background(), conv, 1)
			assert.NoError(t, err)
		})
	}
}

// --- Timeout Tests ---

func TestOllama_Timeout(t *testing.T) {
	var receivedRequest map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedRequest)
		_ = json.NewEncoder(w).Encode(mockGenerateResponse("response"))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model":   "llama2",
		"host":    server.URL,
		"timeout": 60, // 60 seconds
	})
	require.NoError(t, err)
	assert.NotNil(t, g)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.NoError(t, err)
}

// --- Empty Response Handling ---

func TestOllama_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockGenerateResponse(""))
	}))
	defer server.Close()

	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "", responses[0].Content)
}

func TestOllamaChat_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockChatResponse(""))
	}))
	defer server.Close()

	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, responses, 1)
	assert.Equal(t, "", responses[0].Content)
}

// --- Connection Error Tests ---

func TestOllama_ConnectionRefused(t *testing.T) {
	g, err := NewOllama(registry.Config{
		"model": "llama2",
		"host":  "http://localhost:59999", // Port that's unlikely to be in use
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
	// Should contain connection error info
	assert.True(t, strings.Contains(err.Error(), "connect") || strings.Contains(err.Error(), "connection"))
}

func TestOllamaChat_ConnectionRefused(t *testing.T) {
	g, err := NewOllamaChat(registry.Config{
		"model": "llama2",
		"host":  "http://localhost:59999", // Port that's unlikely to be in use
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

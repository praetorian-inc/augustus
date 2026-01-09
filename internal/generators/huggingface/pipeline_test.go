package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestPipelineRegistration(t *testing.T) {
	// Verify generator is registered
	_, ok := generators.Get("huggingface.Pipeline")
	if !ok {
		t.Fatal("huggingface.Pipeline not registered")
	}
}

func TestNewPipelineRequiresModel(t *testing.T) {
	_, err := NewPipeline(registry.Config{})
	if err == nil {
		t.Fatal("expected error when model not provided")
	}
}

func TestPipelineGenerate(t *testing.T) {
	// Create test server mimicking TGI
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("expected path /v1/chat/completions, got %s", r.URL.Path)
		}

		// Parse request
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if len(req.Messages) == 0 {
			t.Error("expected messages in request")
		}

		// Return OpenAI-compatible response
		resp := map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"role":    "assistant",
						"content": "Hello from TGI!",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create generator pointing to test server
	gen, err := NewPipeline(registry.Config{
		"model": "test-model",
		"host":  server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Create conversation
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	// Generate
	messages, err := gen.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	if messages[0].Content != "Hello from TGI!" {
		t.Errorf("expected 'Hello from TGI!', got '%s'", messages[0].Content)
	}
}

func TestPipelineMultipleGenerations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			N int `json:"n"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Return N responses
		choices := make([]map[string]any, req.N)
		for i := 0; i < req.N; i++ {
			choices[i] = map[string]any{
				"message": map[string]string{
					"role":    "assistant",
					"content": fmt.Sprintf("Response %d", i+1),
				},
			}
		}

		resp := map[string]any{"choices": choices}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	gen, _ := NewPipeline(registry.Config{
		"model": "test-model",
		"host":  server.URL,
	})

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	messages, err := gen.Generate(context.Background(), conv, 3)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(messages))
	}
}

func TestPipelineServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"message": "Model is loading",
			},
		})
	}))
	defer server.Close()

	gen, _ := NewPipeline(registry.Config{
		"model": "test-model",
		"host":  server.URL,
	})

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	_, err := gen.Generate(context.Background(), conv, 1)
	if err == nil {
		t.Fatal("expected error for 503 response")
	}

	if !strings.Contains(err.Error(), "Model is loading") {
		t.Errorf("expected 'Model is loading' in error, got: %v", err)
	}
}

func TestPipelineWithSystemPrompt(t *testing.T) {
	var receivedMessages []map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []map[string]string `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		receivedMessages = req.Messages

		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"role": "assistant", "content": "OK"}},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	gen, _ := NewPipeline(registry.Config{
		"model": "test-model",
		"host":  server.URL,
	})

	conv := attempt.NewConversation()
	conv.WithSystem("You are a helpful assistant")
	conv.AddPrompt("Hello")

	_, _ = gen.Generate(context.Background(), conv, 1)

	if len(receivedMessages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(receivedMessages))
	}

	if receivedMessages[0]["role"] != "system" {
		t.Errorf("expected first message role 'system', got '%s'", receivedMessages[0]["role"])
	}
}

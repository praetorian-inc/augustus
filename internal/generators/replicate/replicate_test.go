// Package replicate provides a Replicate generator for Augustus.
package replicate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock Server Helper
// =============================================================================

// mockReplicateServer creates a mock Replicate API server.
// The handler receives the input from the prediction request and can customize output.
type mockReplicateServer struct {
	server        *httptest.Server
	onInput       func(input map[string]any)
	output        any
	callCount     int32
	outputPerCall []any
}

func newMockReplicateServer(output any) *mockReplicateServer {
	m := &mockReplicateServer{
		output: output,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func newMockReplicateServerMulti(outputs []any) *mockReplicateServer {
	m := &mockReplicateServer{
		outputPerCall: outputs,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handler))
	return m
}

func (m *mockReplicateServer) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Handle model lookup - GET /models/{owner}/{name}
	if strings.Contains(r.URL.Path, "/models/") && r.Method == "GET" {
		resp := map[string]any{
			"owner": "meta",
			"name":  "llama-2-7b-chat",
			"latest_version": map[string]any{
				"id": "test-version-id",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Handle prediction creation - POST /predictions
	if strings.Contains(r.URL.Path, "/predictions") && r.Method == "POST" {
		// Parse request to capture input
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)

		if m.onInput != nil {
			if input, ok := req["input"].(map[string]any); ok {
				m.onInput(input)
			}
		}

		count := atomic.AddInt32(&m.callCount, 1)

		// Determine output for this call
		var output any
		if len(m.outputPerCall) > 0 {
			idx := int(count) - 1
			if idx < len(m.outputPerCall) {
				output = m.outputPerCall[idx]
			} else {
				output = m.outputPerCall[len(m.outputPerCall)-1]
			}
		} else {
			output = m.output
		}

		// Return completed prediction immediately
		resp := map[string]any{
			"id":      fmt.Sprintf("prediction-%d", count),
			"version": "test-version-id",
			"status":  "succeeded",
			"output":  output,
			"urls": map[string]string{
				"get":    m.server.URL + fmt.Sprintf("/predictions/prediction-%d", count),
				"cancel": m.server.URL + fmt.Sprintf("/predictions/prediction-%d/cancel", count),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Handle prediction polling - GET /predictions/{id}
	if strings.Contains(r.URL.Path, "/predictions/") && r.Method == "GET" {
		// Extract prediction ID from path
		parts := strings.Split(r.URL.Path, "/")
		predID := parts[len(parts)-1]

		var output any
		if len(m.outputPerCall) > 0 && int(m.callCount) <= len(m.outputPerCall) {
			output = m.outputPerCall[int(m.callCount)-1]
		} else {
			output = m.output
		}

		resp := map[string]any{
			"id":      predID,
			"version": "test-version-id",
			"status":  "succeeded",
			"output":  output,
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

func (m *mockReplicateServer) URL() string {
	return m.server.URL
}

func (m *mockReplicateServer) Close() {
	m.server.Close()
}

// =============================================================================
// Factory Tests
// =============================================================================

func TestNewReplicate_RequiresModel(t *testing.T) {
	cfg := registry.Config{
		"api_key": "test-key",
	}

	_, err := NewReplicate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestNewReplicate_RequiresAPIKey(t *testing.T) {
	// Clear env var if set
	oldVal := os.Getenv("REPLICATE_API_TOKEN")
	os.Unsetenv("REPLICATE_API_TOKEN")
	defer func() {
		if oldVal != "" {
			os.Setenv("REPLICATE_API_TOKEN", oldVal)
		}
	}()

	cfg := registry.Config{
		"model": "meta/llama-2-7b-chat",
	}

	_, err := NewReplicate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestNewReplicate_AcceptsAPIKeyFromConfig(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key-from-config",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)

	r := gen.(*Replicate)
	assert.Equal(t, "meta/llama-2-7b-chat", r.model)
}

func TestNewReplicate_AcceptsAPIKeyFromEnv(t *testing.T) {
	os.Setenv("REPLICATE_API_TOKEN", "test-key-from-env")
	defer os.Unsetenv("REPLICATE_API_TOKEN")

	cfg := registry.Config{
		"model": "meta/llama-2-7b-chat",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
}

func TestNewReplicate_DefaultParameters(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	r := gen.(*Replicate)
	// Python defaults from ReplicateGenerator
	assert.Equal(t, float32(1.0), r.temperature)
	assert.Equal(t, float32(1.0), r.topP)
	assert.Equal(t, float32(1.0), r.repetitionPenalty)
	assert.Equal(t, 9, r.seed) // Default seed from Python
}

func TestNewReplicate_CustomParameters(t *testing.T) {
	cfg := registry.Config{
		"model":              "meta/llama-2-7b-chat",
		"api_key":            "test-key",
		"temperature":        0.7,
		"top_p":              0.9,
		"repetition_penalty": 1.1,
		"max_tokens":         100,
		"seed":               42,
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	r := gen.(*Replicate)
	assert.Equal(t, float32(0.7), r.temperature)
	assert.Equal(t, float32(0.9), r.topP)
	assert.Equal(t, float32(1.1), r.repetitionPenalty)
	assert.Equal(t, 100, r.maxTokens)
	assert.Equal(t, 42, r.seed)
}

// =============================================================================
// Registration Tests
// =============================================================================

func TestRegistration(t *testing.T) {
	names := generators.List()
	found := false
	for _, name := range names {
		if name == "replicate.Replicate" {
			found = true
			break
		}
	}
	assert.True(t, found, "replicate.Replicate should be registered")
}

// =============================================================================
// Interface Compliance Tests
// =============================================================================

func TestImplementsGeneratorInterface(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	// Verify it implements Generator interface
	var _ generators.Generator = gen
}

func TestName(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	assert.Equal(t, "replicate.Replicate", gen.Name())
}

func TestDescription(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.Contains(t, desc, "Replicate")
}

func TestClearHistory(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	// Should not panic
	gen.ClearHistory()
}

// =============================================================================
// Generate Tests (with mock server)
// =============================================================================

func TestGenerate_ZeroGenerations(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	responses, err := gen.Generate(context.Background(), conv, 0)
	require.NoError(t, err)
	assert.Empty(t, responses)
}

func TestGenerate_NegativeGenerations(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	responses, err := gen.Generate(context.Background(), conv, -1)
	require.NoError(t, err)
	assert.Empty(t, responses)
}

func TestGenerate_WithMockServer(t *testing.T) {
	mock := newMockReplicateServer([]string{"Hello from Replicate!"})
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "Hello from Replicate!", responses[0].Content)
}

func TestGenerate_MultipleResponses(t *testing.T) {
	// Replicate doesn't support multiple generations in one call
	// so we loop n times
	mock := newMockReplicateServerMulti([]any{
		[]string{"Response 1"},
		[]string{"Response 2"},
		[]string{"Response 3"},
	})
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	responses, err := gen.Generate(ctx, conv, 3)
	require.NoError(t, err)
	assert.Len(t, responses, 3)
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestGenerate_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"detail": "Model not found",
		})
	}))
	defer server.Close()

	cfg := registry.Config{
		"model":    "nonexistent/model",
		"api_key":  "test-key",
		"base_url": server.URL,
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = gen.Generate(ctx, conv, 1)
	require.Error(t, err)
}

func TestGenerate_ContextCancellation(t *testing.T) {
	// Server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "test-prediction-id",
			"status": "succeeded",
			"output": []string{"Delayed response"},
		})
	}))
	defer server.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": server.URL,
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = gen.Generate(ctx, conv, 1)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "deadline"))
}

// =============================================================================
// Input Formatting Tests
// =============================================================================

func TestGenerate_UsesLastPrompt(t *testing.T) {
	var receivedInput map[string]any
	mock := newMockReplicateServer([]string{"Response"})
	mock.onInput = func(input map[string]any) {
		receivedInput = input
	}
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("First message")
	conv.AddPrompt("Second message")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = gen.Generate(ctx, conv, 1)
	require.NoError(t, err)

	// Python uses prompt.last_message().text
	assert.Equal(t, "Second message", receivedInput["prompt"])
}

func TestGenerate_IncludesParameters(t *testing.T) {
	var receivedInput map[string]any
	mock := newMockReplicateServer([]string{"Response"})
	mock.onInput = func(input map[string]any) {
		receivedInput = input
	}
	defer mock.Close()

	cfg := registry.Config{
		"model":              "meta/llama-2-7b-chat",
		"api_key":            "test-key",
		"base_url":           mock.URL(),
		"temperature":        0.8,
		"top_p":              0.95,
		"repetition_penalty": 1.2,
		"max_tokens":         256,
		"seed":               123,
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test prompt")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = gen.Generate(ctx, conv, 1)
	require.NoError(t, err)

	// Verify all parameters are passed through
	// Use InEpsilon for float comparisons due to float32/64 precision
	assert.InEpsilon(t, 0.8, receivedInput["temperature"], 1e-6)
	assert.InEpsilon(t, 0.95, receivedInput["top_p"], 1e-6)
	assert.InEpsilon(t, 1.2, receivedInput["repetition_penalty"], 1e-6)
	assert.Equal(t, float64(256), receivedInput["max_length"])
	assert.Equal(t, float64(123), receivedInput["seed"])
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestGenerate_EmptyConversation(t *testing.T) {
	cfg := registry.Config{
		"model":   "meta/llama-2-7b-chat",
		"api_key": "test-key",
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()

	// Should return error for empty conversation
	_, err = gen.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no prompts")
}

func TestGenerate_StringOutput(t *testing.T) {
	// Some models return a single string instead of array
	mock := newMockReplicateServer("Single string output")
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "Single string output", responses[0].Content)
}

func TestGenerate_ArrayOutput(t *testing.T) {
	// Models that stream return an array of tokens
	mock := newMockReplicateServer([]string{"Hello", " ", "world", "!"})
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := NewReplicate(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	// Array output should be joined
	assert.Equal(t, "Hello world!", responses[0].Content)
}

// =============================================================================
// Registry Create Test
// =============================================================================

func TestCreateViaRegistry(t *testing.T) {
	mock := newMockReplicateServer([]string{"Test response"})
	defer mock.Close()

	cfg := registry.Config{
		"model":    "meta/llama-2-7b-chat",
		"api_key":  "test-key",
		"base_url": mock.URL(),
	}

	gen, err := generators.Create("replicate.Replicate", cfg)
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, "replicate.Replicate", gen.Name())
}

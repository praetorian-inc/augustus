package xai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockXAIResponse mirrors xAI's OpenAI-compatible Chat Completions response.
func mockXAIResponse(content string) map[string]any {
	return map[string]any{
		"id":      "chatcmpl-grok-test",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "grok-4-vision",
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": content},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 20,
			"total_tokens":      30,
		},
	}
}

func TestXAIGenerator_RequiresModel(t *testing.T) {
	_, err := NewXAI(registry.Config{"api_key": "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestXAIGenerator_RequiresAPIKey(t *testing.T) {
	origKey := os.Getenv("XAI_API_KEY")
	_ = os.Unsetenv("XAI_API_KEY")
	defer func() {
		if origKey != "" {
			_ = os.Setenv("XAI_API_KEY", origKey)
		}
	}()

	_, err := NewXAI(registry.Config{"model": "grok-4-vision"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestXAIGenerator_APIKeyFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-env-key", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockXAIResponse("hi from grok"))
	}))
	defer server.Close()

	t.Setenv("XAI_API_KEY", "test-env-key")

	g, err := NewXAI(registry.Config{
		"model":    "grok-4-vision",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")
	resp, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "hi from grok", resp[0].Content)
}

func TestXAIGenerator_Generate_WithImage(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		b, _ = readAllBody(r)
		capturedBody = b
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockXAIResponse("I see a teapot"))
	}))
	defer server.Close()

	g, err := NewXAI(registry.Config{
		"model":    "grok-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	img := attempt.Image{Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}, MimeType: "image/png"}
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("describe this", []attempt.Image{img}))

	resp, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "I see a teapot", resp[0].Content)

	// xAI uses the standard OpenAI Chat Completions image_url multipart shape
	// (because the API is OpenAI-compatible). Confirm the image data-URI made
	// it onto the wire.
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Messages, 1)
	// Content is a JSON array of parts when images are present.
	var parts []map[string]any
	require.NoError(t, json.Unmarshal(req.Messages[0].Content, &parts))
	require.Len(t, parts, 2, "expected text + image_url parts")
	assert.Equal(t, "text", parts[0]["type"])
	assert.Equal(t, "image_url", parts[1]["type"])
	imgURL := parts[1]["image_url"].(map[string]any)
	assert.Contains(t, imgURL["url"], "data:image/png;base64,")
}

func TestXAIGenerator_Name(t *testing.T) {
	t.Setenv("XAI_API_KEY", "k")
	g, err := NewXAI(registry.Config{"model": "grok-4-vision"})
	require.NoError(t, err)
	assert.Equal(t, "xai.XAI", g.Name())
}

func TestXAIGenerator_RegistersWithRegistry(t *testing.T) {
	_, ok := generators.Registry.Get("xai.XAI")
	assert.True(t, ok, "xai.XAI should be registered in the global generators registry")
}

func TestXAIGenerator_HandlesMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{`)) // truncated
	}))
	defer server.Close()

	g, err := NewXAI(registry.Config{
		"model":    "grok-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err, "expected an error from malformed JSON response")
	// openaicompat wraps with the provider name; check both phrasings
	errStr := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errStr, "json") || strings.Contains(errStr, "unmarshal") ||
			strings.Contains(errStr, "decode") || strings.Contains(errStr, "parse") ||
			strings.Contains(errStr, "unexpected"),
		"expected parse / json error, got: %v", err)
}

func TestXAIGenerator_Handles500Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"internal error","type":"server_error"}}`))
	}))
	defer server.Close()

	g, err := NewXAI(registry.Config{
		"model":    "grok-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	// openaicompat's error wrapping varies; accept any signal of HTTP failure.
	errStr := strings.ToLower(err.Error())
	assert.True(t,
		strings.Contains(errStr, "500") || strings.Contains(errStr, "server") ||
			strings.Contains(errStr, "internal"),
		"expected 5xx signal in error, got: %v", err)
}

func TestXAIGenerator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()

	g, err := NewXAI(registry.Config{
		"model":    "grok-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = g.Generate(ctx, conv, 1)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "deadline"),
		"expected context/deadline error, got: %v", err)
}

// readAllBody is a tiny helper to read an http.Request body without pulling in io.
// (Kept local to avoid an extra import line in a thin test file.)
func readAllBody(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

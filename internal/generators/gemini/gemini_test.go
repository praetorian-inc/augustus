package gemini

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/generators/googleai"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func mockGeminiResponse(text string) map[string]any {
	return map[string]any{
		"candidates": []map[string]any{
			{
				"content": map[string]any{
					"role":  "model",
					"parts": []map[string]any{{"text": text}},
				},
				"finishReason": "STOP",
			},
		},
		"usageMetadata": map[string]any{
			"promptTokenCount":     5,
			"candidatesTokenCount": 7,
			"totalTokenCount":      12,
		},
	}
}

func newTestGenerator(t *testing.T, baseURL string) *Gemini {
	t.Helper()
	g, err := NewGeminiWithOptions(
		WithModel("gemini-2.5-flash"),
		WithAPIKey("test-key"),
		WithBaseURL(baseURL),
	)
	require.NoError(t, err)
	return g
}

func TestNewGemini_RequiresModel(t *testing.T) {
	_, err := NewGemini(registry.Config{"api_key": "x"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestNewGemini_RequiresAPIKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	_, err := NewGemini(registry.Config{"model": "gemini-2.5-flash"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestNewGemini_AcceptsEnvAPIKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "from-env")
	g, err := NewGemini(registry.Config{"model": "gemini-2.5-flash"})
	require.NoError(t, err)
	assert.NotNil(t, g)
}

func TestGeminiGenerator_Generate_TextOnly(t *testing.T) {
	var capturedPath, capturedQuery, capturedAPIKey string
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.RawQuery
		capturedAPIKey = r.Header.Get("x-goog-api-key")
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("hi back"))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hello")

	resp, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "hi back", resp[0].Content)

	// URL shape: {baseURL}/models/{model}:generateContent
	assert.Contains(t, capturedPath, "/models/gemini-2.5-flash:generateContent")
	// API key is sent via the x-goog-api-key header, not the query string,
	// so it cannot leak into URLs or error strings.
	assert.Equal(t, "test-key", capturedAPIKey)
	assert.NotContains(t, capturedQuery, "test-key")

	// Body has plain text part (no inlineData)
	var req googleai.GenerateRequest
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Contents, 1)
	require.Len(t, req.Contents[0].Parts, 1)
	assert.Equal(t, "hello", req.Contents[0].Parts[0].Text)
	assert.Nil(t, req.Contents[0].Parts[0].InlineData)
}

func TestGeminiGenerator_Generate_WithImage(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("I see a teapot"))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	img := attempt.Image{Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}, MimeType: "image/png"}
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("describe", []attempt.Image{img}))

	resp, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resp, 1)
	assert.Equal(t, "I see a teapot", resp[0].Content)

	var req googleai.GenerateRequest
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Contents, 1)
	require.Len(t, req.Contents[0].Parts, 2, "expected text + inlineData parts")

	// Part 0: text
	assert.Equal(t, "describe", req.Contents[0].Parts[0].Text)
	assert.Nil(t, req.Contents[0].Parts[0].InlineData)

	// Part 1: inlineData (base64 of image bytes, matching mimeType)
	assert.Empty(t, req.Contents[0].Parts[1].Text)
	require.NotNil(t, req.Contents[0].Parts[1].InlineData)
	assert.Equal(t, "image/png", req.Contents[0].Parts[1].InlineData.MimeType)
	assert.Equal(t, base64.StdEncoding.EncodeToString(img.Data), req.Contents[0].Parts[1].InlineData.Data)
}

func TestGeminiGenerator_Generate_WithMultipleImages(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("ok"))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	images := []attempt.Image{
		{Data: []byte{0x01}, MimeType: "image/png"},
		{Data: []byte{0x02}, MimeType: "image/jpeg"},
		{Data: []byte{0x03}, MimeType: "image/webp"},
	}
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("compare", images))

	_, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	var req googleai.GenerateRequest
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Contents[0].Parts, 4, "expected 1 text + 3 image parts")

	mimes := []string{}
	for _, p := range req.Contents[0].Parts[1:] {
		require.NotNil(t, p.InlineData)
		mimes = append(mimes, p.InlineData.MimeType)
	}
	assert.Equal(t, []string{"image/png", "image/jpeg", "image/webp"}, mimes)
}

func TestGeminiGenerator_Generate_WithSystemInstruction(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("ack"))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	sys := attempt.NewSystemMessage("you are concise")
	conv.System = &sys
	conv.AddPrompt("hi")

	_, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	var req googleai.GenerateRequest
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.NotNil(t, req.SystemInstruction, "system prompt should travel via systemInstruction, not contents")
	require.Len(t, req.SystemInstruction.Parts, 1)
	assert.Equal(t, "you are concise", req.SystemInstruction.Parts[0].Text)
	// And the contents array must NOT include the system message
	require.Len(t, req.Contents, 1)
	assert.Equal(t, "user", req.Contents[0].Role)
}

func TestGeminiGenerator_GenerateMultiple(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("r" + string(rune('0'+calls))))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	resps, err := g.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	require.Len(t, resps, 3)
	assert.Equal(t, 3, calls)
}

func TestGeminiGenerator_HandlesRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"quota","status":"RESOURCE_EXHAUSTED"}}`))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err := g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "rate limit")
}

func TestGeminiGenerator_HandlesAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"bad key","status":"UNAUTHENTICATED"}}`))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err := g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}

func TestGeminiGenerator_AccumulatesTokenUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGeminiResponse("hi back"))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hello")

	// Before any call, no tokens accumulated.
	assert.Equal(t, int64(0), g.AccumulatedTokens())

	// mockGeminiResponse reports totalTokenCount=12 per call.
	_, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(12), g.AccumulatedTokens())

	// Two more generations accumulate (n=2 → 2×12).
	_, err = g.Generate(context.Background(), conv, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(36), g.AccumulatedTokens())
}

func TestGeminiGenerator_NoUsageMetadataAddsZero(t *testing.T) {
	// A response with no usageMetadata must add 0, never fabricate a count.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hello")

	_, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(0), g.AccumulatedTokens())
}

func TestGeminiGenerator_SatisfiesUsageReporter(t *testing.T) {
	g := newTestGenerator(t, "http://example")
	var _ types.UsageReporter = g
}

func TestGeminiGenerator_Name(t *testing.T) {
	g := newTestGenerator(t, "http://example")
	assert.Equal(t, "gemini.Gemini", g.Name())
}

func TestGeminiGenerator_RegistersWithRegistry(t *testing.T) {
	// init() in gemini.go calls generators.Register, so the factory must be available.
	_, ok := generators.Registry.Get("gemini.Gemini")
	assert.True(t, ok, "gemini.Gemini should be registered in the global generators registry")
}

func TestGeminiGenerator_HandlesMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"candidates": [{"content":`)) // truncated
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err := g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse response",
		"expected error to wrap parse failure, got: %v", err)
}

func TestGeminiGenerator_Handles500Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":500,"message":"internal","status":"INTERNAL"}}`))
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err := g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "server error",
		"expected 5xx classified as server error, got: %v", err)
}

func TestGeminiGenerator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()

	g := newTestGenerator(t, server.URL)
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := g.Generate(ctx, conv, 1)
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "context") || strings.Contains(err.Error(), "deadline"),
		"expected context/deadline error, got: %v", err)
}

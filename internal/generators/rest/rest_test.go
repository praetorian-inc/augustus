package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestRestGenerator_Name(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	if got := g.Name(); got != "rest.Rest" {
		t.Errorf("Name() = %q, want %q", got, "rest.Rest")
	}
}

func TestRestGenerator_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	desc := g.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestRestGenerator_RequiresURI(t *testing.T) {
	_, err := NewRest(registry.Config{})
	if err == nil {
		t.Error("NewRest() with no URI should return error")
	}
}

func TestRestGenerator_Generate_PlainText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello from server"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "Hello from server" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "Hello from server")
	}

	if responses[0].Role != attempt.RoleAssistant {
		t.Errorf("Generate() role = %v, want %v", responses[0].Role, attempt.RoleAssistant)
	}
}

func TestRestGenerator_Generate_MultipleResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 3)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 3 {
		t.Fatalf("Generate() returned %d responses, want 3", len(responses))
	}

	for i, resp := range responses {
		if resp.Content != "response" {
			t.Errorf("responses[%d].Content = %q, want %q", i, resp.Content, "response")
		}
	}
}

func TestRestGenerator_Generate_JSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"response": "JSON response",
			"status":   "ok",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":                 server.URL,
		"response_json":       true,
		"response_json_field": "response",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "JSON response" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "JSON response")
	}
}

func TestRestGenerator_Generate_JSONPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"text": "nested response",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":                 server.URL,
		"response_json":       true,
		"response_json_field": "$.data.text",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "nested response" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "nested response")
	}
}

func TestRestGenerator_Generate_RequestTemplate(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":          server.URL,
		"req_template": `{"prompt": "$INPUT"}`,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("hello world")

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	expected := `{"prompt": "hello world"}`
	if receivedBody != expected {
		t.Errorf("Request body = %q, want %q", receivedBody, expected)
	}
}

func TestRestGenerator_Generate_RequestTemplateWithKey(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":          server.URL,
		"req_template": `{"prompt": "$INPUT", "key": "$KEY"}`,
		"api_key":      "test-api-key",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	expected := `{"prompt": "test", "key": "test-api-key"}`
	if receivedBody != expected {
		t.Errorf("Request body = %q, want %q", receivedBody, expected)
	}
}

func TestRestGenerator_Generate_Headers(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
		"headers": map[string]any{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer $KEY",
		},
		"api_key": "my-api-key",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want %q", receivedHeaders.Get("X-Custom-Header"), "custom-value")
	}

	if receivedHeaders.Get("Authorization") != "Bearer my-api-key" {
		t.Errorf("Authorization = %q, want %q", receivedHeaders.Get("Authorization"), "Bearer my-api-key")
	}
}

func TestRestGenerator_Generate_HTTPMethods(t *testing.T) {
	tests := []struct {
		method       string
		wantMethod   string
	}{
		{"get", "GET"},
		{"GET", "GET"},
		{"post", "POST"},
		{"POST", "POST"},
		{"put", "PUT"},
		{"patch", "PATCH"},
		{"delete", "DELETE"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			var receivedMethod string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()

			g, err := NewRest(registry.Config{
				"uri":    server.URL,
				"method": tt.method,
			})
			if err != nil {
				t.Fatalf("NewRest() error = %v", err)
			}

			conv := attempt.NewConversation()
			conv.AddPrompt("test")

			_, err = g.Generate(context.Background(), conv, 1)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if receivedMethod != tt.wantMethod {
				t.Errorf("Method = %q, want %q", receivedMethod, tt.wantMethod)
			}
		})
	}
}

func TestRestGenerator_Generate_InvalidMethod(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %q, want POST (default)", r.Method)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Invalid method should default to POST
	g, err := NewRest(registry.Config{
		"uri":    server.URL,
		"method": "INVALID",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
}

func TestRestGenerator_Generate_RateLimitCode(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":             server.URL,
		"ratelimit_codes": []any{429},
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Should return an error for rate limit since we don't have backoff
	_, err = g.Generate(context.Background(), conv, 1)
	if err == nil {
		t.Error("Generate() should return error on rate limit")
	}
}

func TestRestGenerator_Generate_SkipCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":        server.URL,
		"skip_codes": []any{204},
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Skip code should return empty response
	if responses[0].Content != "" {
		t.Errorf("Generate() content = %q, want empty string", responses[0].Content)
	}
}

func TestRestGenerator_Generate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err == nil {
		t.Error("Generate() should return error on server error")
	}
}

func TestRestGenerator_Generate_ClientError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err == nil {
		t.Error("Generate() should return error on client error")
	}
}

func TestRestGenerator_Generate_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte("too slow"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":             server.URL,
		"request_timeout": 0.05, // 50ms timeout
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err == nil {
		t.Error("Generate() should return error on timeout")
	}
}

func TestRestGenerator_Generate_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = g.Generate(ctx, conv, 1)
	if err == nil {
		t.Error("Generate() should return error on context cancellation")
	}
}

func TestRestGenerator_Generate_JSONEscapeInput(t *testing.T) {
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":          server.URL,
		"req_template": `{"prompt": "$INPUT"}`,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt(`hello "world"`)

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should properly escape quotes
	expected := `{"prompt": "hello \"world\""}`
	if receivedBody != expected {
		t.Errorf("Request body = %q, want %q", receivedBody, expected)
	}
}

func TestRestGenerator_Generate_GETMethod(t *testing.T) {
	var receivedParams string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedParams = r.URL.RawQuery
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":          server.URL,
		"method":       "GET",
		"req_template": "query=test",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err = g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// For GET requests, params should be in query string
	if !strings.Contains(receivedParams, "query") {
		t.Errorf("Query params = %q, should contain query parameter", receivedParams)
	}
}

func TestRestGenerator_ClearHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() after ClearHistory error = %v", err)
	}
	if len(responses) != 1 {
		t.Errorf("Generate() returned %d responses, want 1", len(responses))
	}
}

func TestRestGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("rest.Rest")
	if !ok {
		t.Fatal("rest.Rest not registered in generators registry")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	// Test factory creates valid generator
	g, err := factory(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if g.Name() != "rest.Rest" {
		t.Errorf("factory created generator with name %q, want %q", g.Name(), "rest.Rest")
	}
}

func TestRestGenerator_JSONResponseArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]any{
			{"text": "response1"},
			{"text": "response2"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri":                 server.URL,
		"response_json":       true,
		"response_json_field": "text",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should extract from first item
	if len(responses) < 1 {
		t.Fatal("Generate() returned no responses")
	}

	if responses[0].Content != "response1" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "response1")
	}
}

func TestRestGenerator_ResponseJSONValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	// response_json=true but no response_json_field should error
	_, err := NewRest(registry.Config{
		"uri":           server.URL,
		"response_json": true,
	})
	if err == nil {
		t.Error("NewRest() should error when response_json=true but response_json_field not set")
	}

	// response_json=true but empty response_json_field should error
	_, err = NewRest(registry.Config{
		"uri":                 server.URL,
		"response_json":       true,
		"response_json_field": "",
	})
	if err == nil {
		t.Error("NewRest() should error when response_json_field is empty string")
	}
}

func TestRestGenerator_ProxyConfiguration(t *testing.T) {
	// Test proxy via config parameter
	g, err := NewRest(registry.Config{
		"uri":   "http://example.com",
		"proxy": "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	// Verify proxy is configured
	if g.(*Rest).proxyURL == nil {
		t.Error("Proxy URL should be configured")
	}

	expectedProxy := "http://127.0.0.1:8080"
	if g.(*Rest).proxyURL.String() != expectedProxy {
		t.Errorf("Proxy URL = %q, want %q", g.(*Rest).proxyURL.String(), expectedProxy)
	}
}

func TestRestGenerator_ProxyInvalidURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	// Invalid proxy URL should return error
	_, err := NewRest(registry.Config{
		"uri":   server.URL,
		"proxy": "://invalid-url",
	})
	if err == nil {
		t.Error("NewRest() should error with invalid proxy URL")
	}
}

func TestRestGenerator_SSEResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Simulate SSE stream with data: prefixed lines
		_, _ = w.Write([]byte("data: {\"delta\":{\"text\":\"Hello \"}}\n\n"))
		_, _ = w.Write([]byte("data: {\"delta\":{\"text\":\"World\"}}\n\n"))
		_, _ = w.Write([]byte("data: {\"delta\":{\"text\":\"!\"}}\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Should concatenate all text fragments from SSE stream
	expected := "Hello World!"
	if responses[0].Content != expected {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, expected)
	}
}

func TestRestGenerator_SSEResponseWithMessageParts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Test alternative SSE format with message.parts structure
		_, _ = w.Write([]byte("data: {\"message\":{\"parts\":[{\"text\":\"SSE text\"}]}}\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "SSE text" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "SSE text")
	}
}

func TestRestGenerator_SSEResponseDirectText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Test SSE format with direct text field
		_, _ = w.Write([]byte("data: {\"text\":\"Direct text\"}\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "Direct text" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "Direct text")
	}
}

func TestRestGenerator_SSEResponseContentField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Test SSE format with content field
		_, _ = w.Write([]byte("data: {\"content\":\"Content field text\"}\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "Content field text" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "Content field text")
	}
}

func TestRestGenerator_SSEResponseFallbackToRaw(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// SSE without recognizable JSON structure - should fallback to raw
		_, _ = w.Write([]byte("data: Plain text response\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Should return raw body when no structured text extracted
	if !strings.Contains(responses[0].Content, "Plain text response") {
		t.Errorf("Generate() content = %q, should contain 'Plain text response'", responses[0].Content)
	}
}

func TestRestGenerator_SSEResponseEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Empty SSE stream
		_, _ = w.Write([]byte(""))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Empty SSE stream should return empty content
	if responses[0].Content != "" {
		t.Errorf("Generate() content = %q, want empty string", responses[0].Content)
	}
}

func TestRestGenerator_NonSSEResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Regular response without SSE content-type
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("Regular response"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Should use normal parsing path, not SSE
	if responses[0].Content != "Regular response" {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, "Regular response")
	}
}

func TestRestGenerator_SSEMixedWithNonJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Mix of valid JSON and non-JSON lines
		_, _ = w.Write([]byte("data: {\"delta\":{\"text\":\"Valid\"}}\n\n"))
		_, _ = w.Write([]byte("event: ping\n\n"))
		_, _ = w.Write([]byte("data: {\"delta\":{\"text\":\" text\"}}\n\n"))
		_, _ = w.Write([]byte(": comment\n\n"))
	}))
	defer server.Close()

	g, err := NewRest(registry.Config{
		"uri": server.URL,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Should extract only valid JSON data lines
	expected := "Valid text"
	if responses[0].Content != expected {
		t.Errorf("Generate() content = %q, want %q", responses[0].Content, expected)
	}
}

func TestRestGenerator_RateLimitConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	tests := []struct {
		name          string
		rateLimit     any
		expectLimiter bool
	}{
		{"no rate limit", nil, false},
		{"rate limit as float64", 10.0, true},
		{"rate limit as int", 5, true},
		{"rate limit zero", 0.0, false},
		{"rate limit fractional", 0.5, true}, // 1 request per 2 seconds
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := registry.Config{
				"uri": server.URL,
			}
			if tt.rateLimit != nil {
				cfg["rate_limit"] = tt.rateLimit
			}

			gen, err := NewRest(cfg)
			if err != nil {
				t.Fatalf("NewRest() error = %v", err)
			}

			rest := gen.(*Rest)
			if tt.expectLimiter && rest.limiter == nil {
				t.Error("expected limiter to be set, got nil")
			}
			if !tt.expectLimiter && rest.limiter != nil {
				t.Error("expected no limiter, got non-nil")
			}
		})
	}
}

func TestRestGenerator_RateLimitEnforced(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	// Set rate limit to 100 requests per second (fast enough for testing)
	gen, err := NewRest(registry.Config{
		"uri":        server.URL,
		"rate_limit": 100.0,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	rest := gen.(*Rest)
	if rest.limiter == nil {
		t.Fatal("limiter should be configured")
	}

	// Make multiple requests - they should all succeed
	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	for i := 0; i < 5; i++ {
		msgs, err := gen.Generate(context.Background(), conv, 1)
		if err != nil {
			t.Fatalf("Generate() error on iteration %d: %v", i, err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Generate() returned %d messages, want 1", len(msgs))
		}
	}

	if requestCount != 5 {
		t.Errorf("expected 5 requests, got %d", requestCount)
	}
}

func TestRestGenerator_RateLimitFractional(t *testing.T) {
	// Test that fractional rate limits (< 1.0) work correctly
	// This was a bug where rate_limit < 1.0 would cause infinite blocking
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()

	// rate_limit: 0.5 = 1 request per 2 seconds
	gen, err := NewRest(registry.Config{
		"uri":        server.URL,
		"rate_limit": 0.5,
	})
	if err != nil {
		t.Fatalf("NewRest() error = %v", err)
	}

	rest := gen.(*Rest)
	if rest.limiter == nil {
		t.Fatal("limiter should be configured for fractional rate")
	}

	// Make 2 requests with a timeout - should not block forever
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	start := time.Now()
	for i := 0; i < 2; i++ {
		msgs, err := gen.Generate(ctx, conv, 1)
		if err != nil {
			t.Fatalf("Generate() error on iteration %d: %v", i, err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Generate() returned %d messages, want 1", len(msgs))
		}
	}
	elapsed := time.Since(start)

	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}

	// With rate_limit=0.5, second request should wait ~2 seconds
	// Allow some tolerance for test timing
	if elapsed < 1*time.Second {
		t.Errorf("expected rate limiting delay, but elapsed time was only %v", elapsed)
	}
}

// Package http provides a shared HTTP client for Venator generators and buffs.
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient_Default(t *testing.T) {
	client := NewClient()

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Client == nil {
		t.Fatal("expected non-nil http.Client")
	}
	if client.BaseURL != "" {
		t.Errorf("expected empty BaseURL, got %q", client.BaseURL)
	}
}

func TestNewClient_WithBaseURL(t *testing.T) {
	client := NewClient(WithBaseURL("https://example.com"))

	if client.BaseURL != "https://example.com" {
		t.Errorf("expected BaseURL 'https://example.com', got %q", client.BaseURL)
	}
}

func TestNewClient_WithHeader(t *testing.T) {
	client := NewClient(WithHeader("X-Custom", "test-value"))

	if v, ok := client.Headers["X-Custom"]; !ok || v != "test-value" {
		t.Errorf("expected header X-Custom='test-value', got %v", client.Headers)
	}
}

func TestNewClient_WithBearerToken(t *testing.T) {
	client := NewClient(WithBearerToken("secret-token"))

	if v, ok := client.Headers["Authorization"]; !ok || v != "Bearer secret-token" {
		t.Errorf("expected Authorization header, got %v", client.Headers)
	}
}

func TestNewClient_WithTimeout(t *testing.T) {
	client := NewClient(WithTimeout(5 * time.Second))

	if client.Client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Client.Timeout)
	}
}

func TestClient_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"hello"}`))
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	resp, err := client.Get(context.Background(), "/test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"message":"hello"}` {
		t.Errorf("unexpected body: %s", string(resp.Body))
	}
}

func TestClient_Post(t *testing.T) {
	var receivedBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	body := map[string]any{"key": "value"}
	resp, err := client.Post(context.Background(), "/api", body)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if receivedBody["key"] != "value" {
		t.Errorf("expected key=value in body, got %v", receivedBody)
	}
}

func TestClient_PostJSON_TypedResponse(t *testing.T) {
	type Response struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message":"success","code":42}`))
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	resp, err := client.Post(context.Background(), "/api", nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result Response
	if err := resp.JSON(&result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if result.Message != "success" || result.Code != 42 {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestClient_HeadersPropagated(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithBearerToken("my-token"),
	)
	_, err := client.Get(context.Background(), "/test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer my-token" {
		t.Errorf("expected 'Bearer my-token', got %q", receivedAuth)
	}
}

func TestClient_UserAgent(t *testing.T) {
	var receivedUA string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(
		WithBaseURL(server.URL),
		WithUserAgent("Venator/1.0"),
	)
	_, err := client.Get(context.Background(), "/test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedUA != "Venator/1.0" {
		t.Errorf("expected 'Venator/1.0', got %q", receivedUA)
	}
}

func TestClient_Do_CustomRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	req, _ := http.NewRequest(http.MethodPut, server.URL+"/update", nil)
	resp, err := client.Do(context.Background(), req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", resp.StatusCode)
	}
}

func TestClient_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	client := NewClient(WithBaseURL(server.URL))
	resp, err := client.Get(context.Background(), "/fail")

	// Should not return error for non-2xx (caller decides how to handle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := NewClient(WithBaseURL(server.URL))
	_, err := client.Get(ctx, "/slow")

	if err == nil {
		t.Fatal("expected error due to cancelled context")
	}
}

func TestResponse_JSON_InvalidJSON(t *testing.T) {
	resp := &Response{
		Body: []byte(`not valid json`),
	}

	var result map[string]any
	err := resp.JSON(&result)

	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

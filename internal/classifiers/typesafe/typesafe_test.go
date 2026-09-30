package typesafe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

func TestNew_EmptyAPIKey(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New() with empty APIKey: want error")
	}
}

func TestClassify_HappyPath(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["model"] != "jev-latest" {
			t.Errorf("model = %v, want jev-latest", req["model"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers":{"vulnerable":{"noul":0.91}}}`))
	}))
	defer srv.Close()

	c, err := New(Config{
		Endpoint:   srv.URL,
		APIKey:     "test-key",
		HTTPClient: srv.Client(),
		Hi:         types.DefaultClassifierHi,
		Lo:         types.DefaultClassifierLo,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result, err := c.Classify(context.Background(), types.Question{
		Instructions: "Did the target output achieve this attack goal?",
		TrueCase:     "true",
		FalseCase:    "false",
		Evidence:     "Goal: x\nPrompt: y\nOutput: z",
	})
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-key")
	}
	if result.P != 0.91 {
		t.Errorf("P = %v, want 0.91", result.P)
	}
	if result.Verdict != types.VerdictVulnerable {
		t.Errorf("Verdict = %s, want vulnerable", result.Verdict)
	}
}

func TestClassify_HTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := mustClient(t, srv)
	_, err := c.Classify(context.Background(), types.Question{})
	if err == nil {
		t.Fatal("Classify() 500: want error")
	}
}

func TestClassify_MissingNoul(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers":{"vulnerable":{}}}`))
	}))
	defer srv.Close()

	c := mustClient(t, srv)
	_, err := c.Classify(context.Background(), types.Question{})
	if err == nil {
		t.Fatal("Classify() missing noul: want error")
	}
}

func TestClassify_NoulOutOfRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"answers":{"vulnerable":{"noul":1.5}}}`))
	}))
	defer srv.Close()

	c := mustClient(t, srv)
	_, err := c.Classify(context.Background(), types.Question{})
	if err == nil {
		t.Fatal("Classify() noul 1.5: want error")
	}
}

func mustClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{
		Endpoint:   srv.URL,
		APIKey:     "test-key",
		HTTPClient: srv.Client(),
		Hi:         types.DefaultClassifierHi,
		Lo:         types.DefaultClassifierLo,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

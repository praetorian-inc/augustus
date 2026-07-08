package mcp

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// headerTransport must substitute $KEY (static api_key) and $VARNAME hook vars
// from the PER-REQUEST context, so credentials provided by a prepare/setup hook
// (e.g. Authorization: Bearer $TOKEN) reach MCP HTTP/SSE requests instead of
// shipping the literal placeholder.
func TestHeaderTransport_SubstitutesHookVarsPerRequest(t *testing.T) {
	var got http.Header
	stub := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Clone()
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	ht := &headerTransport{
		base:   stub,
		apiKey: "static-key",
		headers: map[string]string{
			"Authorization": "Bearer $TOKEN",
			"X-Api-Key":     "$KEY",
		},
	}

	ctx := types.WithHookVars(context.Background(), map[string]string{"TOKEN": "hooked-secret"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	if _, err := ht.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	if h := got.Get("Authorization"); h != "Bearer hooked-secret" {
		t.Errorf("Authorization = %q, want %q", h, "Bearer hooked-secret")
	}
	if h := got.Get("X-Api-Key"); h != "static-key" {
		t.Errorf("X-Api-Key = %q, want %q", h, "static-key")
	}
}

// Longest-first substitution: $ID_TOKEN must resolve before $ID.
func TestHeaderTransport_LongestKeyFirst(t *testing.T) {
	var got http.Header
	stub := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Clone()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	ht := &headerTransport{
		base:    stub,
		headers: map[string]string{"X-Tok": "$ID_TOKEN"},
	}
	ctx := types.WithHookVars(context.Background(), map[string]string{"ID": "short", "ID_TOKEN": "long"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/", nil)
	if _, err := ht.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if h := got.Get("X-Tok"); h != "long" {
		t.Errorf("X-Tok = %q, want %q (longest-first substitution)", h, "long")
	}
}

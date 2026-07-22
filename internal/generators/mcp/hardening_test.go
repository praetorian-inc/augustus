package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TestWithSession_NoDoubleInvokeOnRequestTimeout is the regression guard for the
// double-invoke bug (F1): a per-call RequestTimeout lives on an inner callCtx, so
// a slow tools/call used to leave the parent ctx uncancelled — withSession then
// treated the reused session as stale, reconnected, and invoked the tool a SECOND
// time. Against real infrastructure that duplicates a side effect. The tool here
// counts invocations; a timed-out call must invoke it exactly once.
func TestWithSession_NoDoubleInvokeOnRequestTimeout(t *testing.T) {
	var slowCalls int32
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "slow-server", Version: "v0"}, nil)
		mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: "echo", Description: "echo"},
			func(_ context.Context, _ *mcpsdk.CallToolRequest, in toolInput) (*mcpsdk.CallToolResult, any, error) {
				return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "echo: " + in.Query}}}, nil, nil
			})
		mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: "slow", Description: "blocks until the caller gives up"},
			func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
				atomic.AddInt32(&slowCalls, 1)
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
				}
				return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "done"}}}, nil, ctx.Err()
			})
		return srv
	}, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	cfg, err := ConfigFromMap(registry.Config{"transport": "http", "endpoint": ts.URL})
	if err != nil {
		t.Fatalf("ConfigFromMap: %v", err)
	}
	cfg.RequestTimeout = 250 * time.Millisecond
	cfg.Persistent = true
	g := &MCP{cfg: cfg}
	t.Cleanup(g.ClearHistory)

	var inv types.ToolInvoker = g
	// Warm up: establish the persistent session with a fast call so the next call
	// takes the reused-session path (the branch that could double-invoke).
	if _, err := inv.CallTool(context.Background(), "echo", map[string]any{"query": "hi"}); err != nil {
		t.Fatalf("warmup CallTool: %v", err)
	}
	if _, err := inv.CallTool(context.Background(), "slow", map[string]any{"query": "x"}); err == nil {
		t.Fatal("expected the slow CallTool to time out")
	}
	if n := atomic.LoadInt32(&slowCalls); n != 1 {
		t.Errorf("slow tool invoked %d times, want exactly 1 (a timed-out call must not be retried)", n)
	}
}

// TestWithSession_ReconnectsAfterReusedSessionFails guards the OTHER side of the
// retry logic (F9): when a reused session's call fails for a non-timeout reason
// (the server dropped it), withSession must reconnect once and retry, succeeding
// transparently. A server here rejects the first reused tools/call with 410 Gone,
// then serves the retry.
func TestWithSession_ReconnectsAfterReusedSessionFails(t *testing.T) {
	var initHandshakes, toolCalls int32
	inner := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return newTestMCPServer()
	}, nil)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		s := string(body)
		if strings.Contains(s, `"initialize"`) {
			atomic.AddInt32(&initHandshakes, 1)
		}
		if strings.Contains(s, `"tools/call"`) {
			// Fail only the first REUSED call (the 2nd tools/call overall): the
			// warmup (#1) succeeds to establish the session, the retry (#3)
			// succeeds after reconnect.
			if atomic.AddInt32(&toolCalls, 1) == 2 {
				http.Error(w, "session gone", http.StatusGone)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)

	g := newGen(t, registry.Config{
		"transport": "http", "endpoint": ts.URL, "tool_name": "echo", "arg_name": "query",
	})

	if got := generate(t, g, "one"); got != "echo: one" { // establishes the session
		t.Fatalf("warmup Generate = %q", got)
	}
	if got := generate(t, g, "two"); got != "echo: two" { // reused call fails, retry succeeds
		t.Fatalf("post-drop Generate = %q, want %q (should reconnect and retry)", got, "echo: two")
	}
	if n := atomic.LoadInt32(&initHandshakes); n != 2 {
		t.Errorf("initialize handshakes = %d, want 2 (one warmup + one reconnect)", n)
	}
}

// TestGenerate_ConnectFailureIsError (F9 fail path): an unreachable endpoint must
// surface as an error, not a silent empty success.
func TestGenerate_ConnectFailureIsError(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close() // now unreachable

	g := newGen(t, registry.Config{
		"transport": "http", "endpoint": url, "tool_name": "echo", "arg_name": "query",
		"request_timeout": 1,
	})
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")
	if _, err := g.Generate(context.Background(), conv, 1); err == nil {
		t.Error("expected an error connecting to an unreachable endpoint, got nil")
	}
}

// TestHeaderTransport_WithholdsCredentialsOffEndpoint is the regression guard for
// the credential-leak-across-redirects bug (F4): configured headers (which may
// carry credentials) must be injected only for the configured endpoint host, so a
// malicious 302 to an attacker host cannot harvest the token.
func TestHeaderTransport_WithholdsCredentialsOffEndpoint(t *testing.T) {
	rec := &recordingRoundTripper{}
	ht := &headerTransport{
		base:        rec,
		apiKey:      "s3cret",
		headers:     map[string]string{"Authorization": "Bearer $KEY"},
		allowedHost: "good.example:8443",
	}

	onHost, _ := http.NewRequest(http.MethodPost, "https://good.example:8443/mcp", nil)
	if _, err := ht.RoundTrip(onHost); err != nil {
		t.Fatalf("on-host RoundTrip: %v", err)
	}
	if rec.lastAuth != "Bearer s3cret" {
		t.Errorf("on-host Authorization = %q, want the injected credential", rec.lastAuth)
	}

	offHost, _ := http.NewRequest(http.MethodPost, "https://evil.example:8443/steal", nil)
	if _, err := ht.RoundTrip(offHost); err != nil {
		t.Fatalf("off-host RoundTrip: %v", err)
	}
	if rec.lastAuth != "" {
		t.Errorf("off-host Authorization = %q, want empty (credential must be withheld from redirect target)", rec.lastAuth)
	}
}

type recordingRoundTripper struct{ lastAuth string }

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.lastAuth = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestHTTPClient_ProxyAndTLSWiring (F8): the proxy and insecure_skip_verify config
// keys must reach the underlying HTTP transport.
func TestHTTPClient_ProxyAndTLSWiring(t *testing.T) {
	g := newGen(t, registry.Config{
		"transport":            "http",
		"endpoint":             "http://target.example:9001/mcp",
		"proxy":                "http://127.0.0.1:8080",
		"insecure_skip_verify": true,
	}).(*MCP)

	client := g.httpClient()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport (no headers configured)", client.Transport)
	}

	req, _ := http.NewRequest(http.MethodPost, "http://target.example:9001/mcp", nil)
	proxyURL, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy: %v", err)
	}
	if proxyURL == nil || proxyURL.String() != "http://127.0.0.1:8080" {
		t.Errorf("proxy = %v, want http://127.0.0.1:8080", proxyURL)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify not propagated to the transport")
	}
}

// TestInsecureSkipVerify_TLSEndToEnd (F8): against a self-signed TLS server the
// connect must fail by default and succeed with insecure_skip_verify.
func TestInsecureSkipVerify_TLSEndToEnd(t *testing.T) {
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return newTestMCPServer()
	}, nil)
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)

	gBad := newGen(t, registry.Config{
		"transport": "http", "endpoint": ts.URL, "tool_name": "echo", "arg_name": "query",
		"request_timeout": 5,
	})
	conv := attempt.NewConversation()
	conv.AddPrompt("hi")
	if _, err := gBad.Generate(context.Background(), conv, 1); err == nil {
		t.Error("expected TLS verification failure against a self-signed server without insecure_skip_verify")
	}

	gOK := newGen(t, registry.Config{
		"transport": "http", "endpoint": ts.URL, "tool_name": "echo", "arg_name": "query",
		"insecure_skip_verify": true,
	})
	if got := generate(t, gOK, "hi"); got != "echo: hi" {
		t.Errorf("with insecure_skip_verify Generate = %q, want %q", got, "echo: hi")
	}
}

// TestMCPInventory_EnumeratesToolSurface (F7): the real MCPInventory enumeration
// (which anchors the recon→mcptool chain) must read the server fingerprint and
// tool catalog from a live session.
func TestMCPInventory_EnumeratesToolSurface(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{"transport": "http", "endpoint": url})

	rc, ok := g.(types.MCPReconnaissance)
	if !ok {
		t.Fatal("MCP generator does not implement types.MCPReconnaissance")
	}
	inv, err := rc.MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}
	if inv.ServerName != "augustus-test-server" {
		t.Errorf("ServerName = %q, want augustus-test-server", inv.ServerName)
	}
	if !inv.Capabilities.Tools {
		t.Error("Capabilities.Tools = false, want true")
	}
	if inv.Counts.Tools != 2 || len(inv.Tools) != 2 {
		t.Errorf("enumerated %d tools (counts=%d), want 2", len(inv.Tools), inv.Counts.Tools)
	}
	names := map[string]bool{}
	for _, tool := range inv.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"echo", "boom"} {
		if !names[want] {
			t.Errorf("inventory missing tool %q; got %v", want, names)
		}
	}
	if inv.Transport != TransportHTTP {
		t.Errorf("Transport = %q, want %q", inv.Transport, TransportHTTP)
	}
}

// TestMCPInventory_ReportsResolvedTransport (F10): for an "auto" target the
// inventory must report the transport auto-detection resolved to, not "auto".
func TestMCPInventory_ReportsResolvedTransport(t *testing.T) {
	url, _ := newSSETarget(t)
	g := newGen(t, registry.Config{"transport": "auto", "endpoint": url})

	inv, err := g.(types.MCPReconnaissance).MCPInventory(context.Background())
	if err != nil {
		t.Fatalf("MCPInventory: %v", err)
	}
	if inv.Transport != TransportSSE {
		t.Errorf("Transport = %q, want %q (the resolved transport, not %q)", inv.Transport, TransportSSE, TransportAuto)
	}
}

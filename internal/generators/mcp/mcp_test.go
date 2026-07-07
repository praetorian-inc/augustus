package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// stdioServerEnv, when set, makes the test binary act as an MCP server speaking
// over stdio instead of running the test suite. The stdio transport test sets
// this on the subprocess it launches via the generator's command config.
const stdioServerEnv = "AUGUSTUS_MCP_TEST_STDIO_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(stdioServerEnv) == "1" {
		srv := newTestMCPServer()
		// Run blocks until the client closes stdin; then exit without running tests.
		_ = srv.Run(context.Background(), &mcpsdk.StdioTransport{})
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type toolInput struct {
	Query string `json:"query" jsonschema:"the text to act on"`
	Actor string `json:"actor,omitempty" jsonschema:"optional caller identity"`
}

// newTestMCPServer builds an MCP server exposing a small, deterministic tool set
// used by both the HTTP and stdio transport tests.
func newTestMCPServer() *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "augustus-test-server", Version: "v0"}, nil)

	mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: "echo", Description: "Echoes the query back."},
		func(_ context.Context, _ *mcpsdk.CallToolRequest, in toolInput) (*mcpsdk.CallToolResult, any, error) {
			text := "echo: " + in.Query
			if in.Actor != "" {
				text += " (actor=" + in.Actor + ")"
			}
			return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: text}}}, nil, nil
		})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{Name: "boom", Description: "Always returns a tool-level error."},
		func(_ context.Context, _ *mcpsdk.CallToolRequest, _ toolInput) (*mcpsdk.CallToolResult, any, error) {
			return &mcpsdk.CallToolResult{
				IsError: true,
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "access denied"}},
			}, nil, nil
		})

	return srv
}

// newHTTPTarget starts an httptest server hosting the MCP server over the
// streamable HTTP transport. It records the last Authorization header seen so
// header-injection can be asserted.
func newHTTPTarget(t *testing.T) (url string, lastAuth func() string) {
	t.Helper()

	var mu sync.Mutex
	var auth string
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return newTestMCPServer()
	}, nil)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			mu.Lock()
			auth = a
			mu.Unlock()
		}
		handler.ServeHTTP(w, r)
	})

	ts := httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)

	return ts.URL, func() string {
		mu.Lock()
		defer mu.Unlock()
		return auth
	}
}

func newGen(t *testing.T, cfg registry.Config) generators.Generator {
	t.Helper()
	g, err := NewMCP(cfg)
	if err != nil {
		t.Fatalf("NewMCP() error = %v", err)
	}
	t.Cleanup(g.ClearHistory)
	return g
}

func generate(t *testing.T, g generators.Generator, prompt string) string {
	t.Helper()
	conv := attempt.NewConversation()
	conv.AddPrompt(prompt)
	resp, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("Generate() returned %d messages, want 1", len(resp))
	}
	return resp[0].Content
}

func TestGenerate_HTTP_ToolCall(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	})

	got := generate(t, g, "hello world")
	if got != "echo: hello world" {
		t.Errorf("Generate() = %q, want %q", got, "echo: hello world")
	}
}

func TestGenerate_HTTP_ListTools(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"mode":      "list_tools",
	})

	got := generate(t, g, "ignored prompt")
	for _, want := range []string{"echo", "Echoes the query back.", "boom", "input_schema"} {
		if !strings.Contains(got, want) {
			t.Errorf("list_tools output missing %q; got:\n%s", want, got)
		}
	}
}

func TestGenerate_HTTP_ToolErrorIsObservation(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "boom",
		"arg_name":  "query",
	})

	// A tool-level error must surface as content, not a Go error: "access denied"
	// is a meaningful observation for an access-control detector.
	got := generate(t, g, "do the thing")
	if !strings.Contains(got, "access denied") {
		t.Errorf("Generate() = %q, want it to contain %q", got, "access denied")
	}
}

func TestGenerate_HTTP_ArgumentsTemplate(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport":          "http",
		"endpoint":           url,
		"tool_name":          "echo",
		"arguments_template": map[string]any{"query": "$INPUT", "actor": "globex"},
	})

	got := generate(t, g, "payload")
	if got != "echo: payload (actor=globex)" {
		t.Errorf("Generate() = %q, want %q", got, "echo: payload (actor=globex)")
	}
}

func TestGenerate_HTTP_InjectsHeaders(t *testing.T) {
	url, lastAuth := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
		"api_key":   "s3cret",
		"headers":   map[string]any{"Authorization": "Bearer $KEY"},
	})

	_ = generate(t, g, "hi")
	if got := lastAuth(); got != "Bearer s3cret" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer s3cret")
	}
}

func TestGenerate_HTTP_LastRawResponse(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	})

	_ = generate(t, g, "raw please")
	raw := g.(*MCP).LastRawResponse()
	if len(raw) == 0 {
		t.Fatal("LastRawResponse() is empty")
	}
	if !strings.Contains(string(raw), "raw please") {
		t.Errorf("LastRawResponse() = %s, want it to contain the echoed prompt", raw)
	}
}

func TestGenerate_Stdio_ToolCall(t *testing.T) {
	g := newGen(t, registry.Config{
		"transport": "stdio",
		"command":   os.Args[0],
		"env":       map[string]any{stdioServerEnv: "1"},
		"tool_name": "echo",
		"arg_name":  "query",
	})

	got := generate(t, g, "over stdio")
	if got != "echo: over stdio" {
		t.Errorf("Generate() = %q, want %q", got, "echo: over stdio")
	}
}

func TestClearHistory_AllowsReuse(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	})

	if got := generate(t, g, "one"); got != "echo: one" {
		t.Fatalf("first Generate() = %q", got)
	}
	g.ClearHistory() // closes the persistent session
	if got := generate(t, g, "two"); got != "echo: two" {
		t.Errorf("post-ClearHistory Generate() = %q, want %q", got, "echo: two")
	}
}

// newSSETarget starts an httptest server hosting the MCP server over the legacy
// HTTP+SSE transport. It returns a counter of how many SSE streams (GET requests)
// were established, so tests can distinguish session reuse from reconnection.
func newSSETarget(t *testing.T) (url string, sseStreams func() int32) {
	t.Helper()

	var gets int32
	handler := mcpsdk.NewSSEHandler(func(*http.Request) *mcpsdk.Server {
		return newTestMCPServer()
	}, nil)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			atomic.AddInt32(&gets, 1)
		}
		handler.ServeHTTP(w, r)
	})

	ts := httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)

	return ts.URL, func() int32 { return atomic.LoadInt32(&gets) }
}

// TestGenerate_SSE_ToolCall exercises the legacy SSE transport end-to-end. It is
// the regression guard for the context-lifetime bug: connect() used to cancel the
// context that owns the SSE GET /sse stream the moment it returned, so the stream
// died before the first tools/call and every SSE request failed. The streamable
// HTTP and stdio tests could not catch it because neither holds a ctx-bound
// persistent stream.
func TestGenerate_SSE_ToolCall(t *testing.T) {
	url, _ := newSSETarget(t)
	g := newGen(t, registry.Config{
		"transport": "sse",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	})

	got := generate(t, g, "hello sse")
	if got != "echo: hello sse" {
		t.Errorf("Generate() = %q, want %q", got, "echo: hello sse")
	}
}

// TestGenerate_SSE_PersistentSessionSurvivesCancelledCallContext guards the
// subtler half of the fix: the persistent session must be bound to a
// generator-lifetime context, not the per-Generate caller context. It cancels
// the first call's context after that call returns, then makes a second call on a
// fresh context, and asserts exactly one SSE stream was established — i.e. the
// live session was reused, not silently torn down and reconnected (which the
// one-shot retry would otherwise mask as a plain success).
func TestGenerate_SSE_PersistentSessionSurvivesCancelledCallContext(t *testing.T) {
	url, sseStreams := newSSETarget(t)
	g := newGen(t, registry.Config{
		"transport": "sse",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	})

	ctx1, cancel1 := context.WithCancel(context.Background())
	conv1 := attempt.NewConversation()
	conv1.AddPrompt("one")
	if _, err := g.Generate(ctx1, conv1, 1); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	cancel1() // cancel the first call's context AFTER it returned

	conv2 := attempt.NewConversation()
	conv2.AddPrompt("two")
	resp, err := g.Generate(context.Background(), conv2, 1)
	if err != nil {
		t.Fatalf("second Generate after first ctx cancelled: %v", err)
	}
	if resp[0].Content != "echo: two" {
		t.Errorf("second Generate = %q, want %q", resp[0].Content, "echo: two")
	}

	if n := sseStreams(); n != 1 {
		t.Errorf("SSE streams established = %d, want 1 (session must be reused, not reconnected)", n)
	}
}

// newCountingHTTPTarget hosts the MCP server over streamable HTTP and counts
// every HTTP request, so memoization can be asserted by request count.
func newCountingHTTPTarget(t *testing.T) (url string, reqCount func() int32) {
	t.Helper()
	var n int32
	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return newTestMCPServer()
	}, nil)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		handler.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)
	return ts.URL, func() int32 { return atomic.LoadInt32(&n) }
}

func TestToolInvoker_ListTools(t *testing.T) {
	url, _ := newHTTPTarget(t)
	inv, ok := newGen(t, registry.Config{
		"transport": "http",
		"endpoint":  url,
		"tool_name": "echo",
		"arg_name":  "query",
	}).(types.ToolInvoker)
	if !ok {
		t.Fatal("MCP generator does not implement types.ToolInvoker")
	}

	tools, err := inv.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := map[string]map[string]any{}
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		got[name] = tm
	}
	for _, want := range []string{"echo", "boom"} {
		if _, ok := got[want]; !ok {
			t.Errorf("ListTools missing tool %q; got %v", want, tools)
		}
	}
	// Canonical wire shape: name + description present, parameters is a schema.
	if d, _ := got["echo"]["description"].(string); d == "" {
		t.Errorf("echo tool missing description; got %v", got["echo"])
	}
	if _, ok := got["echo"]["parameters"]; !ok {
		t.Errorf("echo tool missing parameters schema; got %v", got["echo"])
	}
}

func TestToolInvoker_CallTool(t *testing.T) {
	url, _ := newHTTPTarget(t)
	inv := newGen(t, registry.Config{
		"transport": "http", "endpoint": url, "tool_name": "echo", "arg_name": "query",
	}).(types.ToolInvoker)

	res, err := inv.CallTool(context.Background(), "echo", map[string]any{"query": "direct"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.Text != "echo: direct" {
		t.Errorf("CallTool text = %q, want %q", res.Text, "echo: direct")
	}
	if res.IsError {
		t.Error("CallTool IsError = true, want false")
	}
	if len(res.Raw) == 0 {
		t.Error("CallTool Raw is empty")
	}

	// A tool-level error is an observation (IsError), not a Go error.
	boom, err := inv.CallTool(context.Background(), "boom", map[string]any{"query": "x"})
	if err != nil {
		t.Fatalf("CallTool(boom) returned Go error: %v", err)
	}
	if !boom.IsError {
		t.Error("CallTool(boom) IsError = false, want true")
	}
	if !strings.Contains(boom.Text, "access denied") {
		t.Errorf("CallTool(boom) text = %q, want it to contain %q", boom.Text, "access denied")
	}
}

func TestToolInvoker_ListToolsMemoized(t *testing.T) {
	url, reqs := newCountingHTTPTarget(t)
	inv := newGen(t, registry.Config{
		"transport": "http", "endpoint": url, "tool_name": "echo", "arg_name": "query",
	}).(types.ToolInvoker)

	if _, err := inv.ListTools(context.Background()); err != nil {
		t.Fatalf("first ListTools: %v", err)
	}
	after := reqs()
	if after == 0 {
		t.Fatal("expected the first ListTools to hit the server")
	}
	if _, err := inv.ListTools(context.Background()); err != nil {
		t.Fatalf("second ListTools: %v", err)
	}
	if now := reqs(); now != after {
		t.Errorf("memoized ListTools issued %d extra request(s); want 0", now-after)
	}
}

// TestToolCallValidationDeferred: with no tool_name, construction succeeds and
// the ToolInvoker path works (a toolsec probe uses it), but the tool_call
// Generate path fails loudly at call time.
func TestToolCallValidationDeferred(t *testing.T) {
	url, _ := newHTTPTarget(t)
	g := newGen(t, registry.Config{"transport": "http", "endpoint": url}) // no tool_name/arg_name

	// ToolInvoker path works without tool_name.
	if _, err := g.(types.ToolInvoker).ListTools(context.Background()); err != nil {
		t.Fatalf("ListTools without tool_name: %v", err)
	}

	// Generate (tool_call) path errors, clearly, at call time.
	conv := attempt.NewConversation()
	conv.AddPrompt("x")
	_, err := g.Generate(context.Background(), conv, 1)
	if err == nil || !strings.Contains(err.Error(), "tool_name") {
		t.Fatalf("Generate without tool_name: got %v, want an error mentioning tool_name", err)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := generators.Get("mcp.MCP"); !ok {
		t.Error("generator mcp.MCP is not registered")
	}
}

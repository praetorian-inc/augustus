package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
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

func TestRegistered(t *testing.T) {
	if _, ok := generators.Get("mcp.MCP"); !ok {
		t.Error("generator mcp.MCP is not registered")
	}
}

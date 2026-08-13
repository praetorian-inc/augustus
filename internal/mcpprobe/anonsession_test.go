package mcpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// ---------------------------------------------------------------------------
// Test MCP servers. These are REAL MCP servers (SDK server handlers behind
// httptest) rather than hand-rolled JSON-RPC fixtures, so a session the helper
// establishes exercises the true initialize / tools/list / tools/call path.
// ---------------------------------------------------------------------------

// testServerOpts configures a stub MCP server.
type testServerOpts struct {
	// requireToken, when non-empty, makes the HTTP layer reject any request whose
	// Authorization header does not carry this exact token — a server that
	// genuinely enforces authentication.
	requireToken string
	// sse serves the legacy HTTP+SSE transport instead of streamable HTTP.
	sse bool
}

// newTestMCPServer stands up an MCP server exposing one read-only tool and one
// unannotated tool, optionally behind an authentication gate.
func newTestMCPServer(t *testing.T, opts testServerOpts) (*httptest.Server, string) {
	t.Helper()

	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "stub", Version: "1"}, nil)
	tru := true
	srv.AddTool(&mcpsdk.Tool{
		Name:        "get_status",
		Description: "Return service status",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "status: ok"}}}, nil
	})
	srv.AddTool(&mcpsdk.Tool{
		Name:        "wipe_all",
		Description: "Delete everything",
		Annotations: &mcpsdk.ToolAnnotations{DestructiveHint: &tru},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "wiped"}}}, nil
	})

	var mcpHandler http.Handler
	if opts.sse {
		mcpHandler = mcpsdk.NewSSEHandler(func(*http.Request) *mcpsdk.Server { return srv }, nil)
	} else {
		mcpHandler = mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return srv }, nil)
	}

	gated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.requireToken != "" {
			if r.Header.Get("Authorization") != "Bearer "+opts.requireToken {
				w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mcpHandler.ServeHTTP(w, r)
	})

	ts := httptest.NewServer(gated)
	t.Cleanup(ts.Close)

	endpoint := ts.URL
	if opts.sse {
		endpoint = ts.URL + "/sse"
	}
	return ts, endpoint
}

// stubEndpoint implements types.MCPEndpoint. authToken, when set, is injected by
// HTTPClient only — AnonymousHTTPClient never carries it, mirroring the real
// generator's credential boundary.
type stubEndpoint struct {
	endpoint  string
	transport string
	authToken string
}

func (s stubEndpoint) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (s stubEndpoint) ClearHistory()       {}
func (s stubEndpoint) Name() string        { return "stubEndpoint" }
func (s stubEndpoint) Description() string { return "stubEndpoint" }
func (s stubEndpoint) EndpointURL() string { return s.endpoint }
func (s stubEndpoint) Transport() string   { return s.transport }
func (s stubEndpoint) ProxyURL() *url.URL  { return nil }

func (s stubEndpoint) HTTPClient() *http.Client {
	if s.authToken == "" {
		return &http.Client{Timeout: 10 * time.Second}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: bearerTransport{base: http.DefaultTransport, token: s.authToken},
	}
}

func (s stubEndpoint) AnonymousHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// ConfiguredCredentialHeaders implements CredentialReporter.
func (s stubEndpoint) ConfiguredCredentialHeaders() []string {
	if s.authToken == "" {
		return nil
	}
	return []string{"Authorization"}
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(clone)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestConnectAnonymous_OpenStreamableServer: against an open streamable-HTTP
// server the anonymous session connects and can enumerate and invoke.
func TestConnectAnonymous_OpenStreamableServer(t *testing.T) {
	_, endpoint := newTestMCPServer(t, testServerOpts{})
	ctx := context.Background()

	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: endpoint, transport: "http"}, 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectAnonymous() error = %v, want nil (server is open)", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("ListTools() returned %d tools, want 2", len(tools))
	}
	res, err := sess.CallTool(ctx, "get_status", map[string]any{})
	if err != nil {
		t.Fatalf("CallTool() error = %v", err)
	}
	if !strings.Contains(res.Text, "status: ok") {
		t.Errorf("CallTool() text = %q, want it to contain %q", res.Text, "status: ok")
	}
}

// TestConnectAnonymous_OpenSSEServer: the legacy HTTP+SSE transport works too.
// DVMCP and many deployed servers speak only this transport, so a helper that
// handled streamable HTTP alone would silently skip them.
func TestConnectAnonymous_OpenSSEServer(t *testing.T) {
	_, endpoint := newTestMCPServer(t, testServerOpts{sse: true})
	ctx := context.Background()

	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: endpoint, transport: "sse"}, 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectAnonymous() error = %v, want nil", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("ListTools() returned %d tools, want 2", len(tools))
	}
}

// TestConnectAnonymous_AuthenticatedServerRefuses: a server that genuinely
// enforces authentication must refuse the anonymous session. This is the control
// that keeps the probe from firing on hardened targets.
func TestConnectAnonymous_AuthenticatedServerRefuses(t *testing.T) {
	_, endpoint := newTestMCPServer(t, testServerOpts{requireToken: "goodtoken"})
	ctx := context.Background()

	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: endpoint, transport: "http", authToken: "goodtoken"}, 10*time.Second)
	if err == nil {
		sess.Close()
		t.Fatal("ConnectAnonymous() succeeded against an authenticating server, want an error")
	}
}

// TestConnectAnonymous_CarriesNoCredentials: the helper must borrow
// AnonymousHTTPClient, never HTTPClient. Sending the operator's token would make
// a correctly-hardened server accept us — because we are authenticated, not
// because it is vulnerable — inverting the verdict.
func TestConnectAnonymous_CarriesNoCredentials(t *testing.T) {
	// Guarded: the handler runs on the server's goroutines while the test body
	// reads, so an unsynchronised slice is a data race — and `make test` runs with
	// -race, so this fails the build the moment the timing lands.
	var (
		sawAuthMu sync.Mutex
		sawAuth   []string
	)
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "stub", Version: "1"}, nil)
	srv.AddTool(&mcpsdk.Tool{
		Name:        "get_status",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "ok"}}}, nil
	})
	h := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return srv }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthMu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		sawAuthMu.Unlock()
		h.ServeHTTP(w, r)
	}))
	defer ts.Close()

	ctx := context.Background()
	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: ts.URL, transport: "http", authToken: "secret-token"}, 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectAnonymous() error = %v", err)
	}
	defer sess.Close()
	if _, err := sess.ListTools(ctx); err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}

	sawAuthMu.Lock()
	defer sawAuthMu.Unlock()
	if len(sawAuth) == 0 {
		t.Fatal("server saw no requests")
	}
	for i, got := range sawAuth {
		if got != "" {
			t.Errorf("request %d carried Authorization = %q, want empty (anonymous session must send no credentials)", i, got)
		}
	}
}

// TestConnectAnonymous_AutoTransportFallback: with no declared transport the
// helper must discover a working one rather than skip the target.
func TestConnectAnonymous_AutoTransportFallback(t *testing.T) {
	_, endpoint := newTestMCPServer(t, testServerOpts{sse: true})
	ctx := context.Background()

	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: endpoint, transport: ""}, 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectAnonymous() with auto transport error = %v, want nil", err)
	}
	defer sess.Close()
	if got := sess.Transport(); got != "sse" {
		t.Errorf("Transport() = %q, want %q", got, "sse")
	}
}

// TestConnectAnonymous_ToolMapsCarryAnnotations: the anonymous catalog must
// carry the server's safety annotations in the same shape the authenticated path
// produces, so toolpolicy can gate destructive tools on it.
func TestConnectAnonymous_ToolMapsCarryAnnotations(t *testing.T) {
	_, endpoint := newTestMCPServer(t, testServerOpts{})
	ctx := context.Background()

	sess, err := ConnectAnonymous(ctx, stubEndpoint{endpoint: endpoint, transport: "http"}, 10*time.Second)
	if err != nil {
		t.Fatalf("ConnectAnonymous() error = %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	byName := map[string]map[string]any{}
	for _, tm := range tools {
		name, _ := tm["name"].(string)
		byName[name] = tm
	}
	if _, ok := byName["get_status"]["parameters"]; !ok {
		t.Error("get_status tool map has no \"parameters\" key")
	}
	if !IsReadOnlyTool(byName["get_status"]) {
		t.Error("IsReadOnlyTool(get_status) = false, want true (server annotated it read-only)")
	}
	if IsReadOnlyTool(byName["wipe_all"]) {
		t.Error("IsReadOnlyTool(wipe_all) = true, want false (server annotated it destructive)")
	}
}

// TestConnectAnonymous_NoEndpoint: a target with no URL surface cannot be
// assessed and must return an error rather than a usable session.
func TestConnectAnonymous_NoEndpoint(t *testing.T) {
	if sess, err := ConnectAnonymous(context.Background(), stubEndpoint{}, time.Second); err == nil {
		sess.Close()
		t.Fatal("ConnectAnonymous() with no endpoint succeeded, want an error")
	}
}

// TestIsReadOnlyTool_NameHeuristic: most servers ship no annotations at all, so
// a conventional read-only naming heuristic is the fallback. It must be
// conservative — an unrecognised name is NOT treated as read-only, because the
// invocation proof must never mutate a customer's state.
func TestIsReadOnlyTool_NameHeuristic(t *testing.T) {
	readOnly := []string{
		"get_status", "list_users", "read_file", "show_config", "search_docs",
		"describe_table", "find_item", "query_db", "fetch_url", "view_page",
		"lookup_dns", "info", "count_rows", "check_health", "whoami", "ping",
	}
	for _, name := range readOnly {
		if !IsReadOnlyTool(map[string]any{"name": name}) {
			t.Errorf("IsReadOnlyTool(%q) = false, want true", name)
		}
	}
	notReadOnly := []string{
		"delete_user", "create_order", "update_record", "send_email", "wipe_all",
		"transfer_funds", "execute_command", "remote_access", "manage_permissions",
		"authenticate", "reset_password", "frobnicate",
	}
	for _, name := range notReadOnly {
		if IsReadOnlyTool(map[string]any{"name": name}) {
			t.Errorf("IsReadOnlyTool(%q) = true, want false", name)
		}
	}
}

// TestIsReadOnlyTool_DestructiveNameWinsOverReadOnlySegment locks the fix for a
// compound, UNANNOTATED name that matches BOTH vocabularies. A destructive segment
// must win: otherwise the read-only invocation proof would pick the tool and
// perform its destructive half against a customer's target.
func TestIsReadOnlyTool_DestructiveNameWinsOverReadOnlySegment(t *testing.T) {
	// Each name has a read-only segment (status/report/check/list) AND a destructive
	// one (reset/clear/rotate/flush/purge). Before the fix the read-only match won.
	for _, name := range []string{
		"reset_status", "clear_status", "rotate_report", "flush_and_check", "purge_list",
	} {
		tm := map[string]any{"name": name}
		if IsReadOnlyTool(tm) {
			t.Errorf("IsReadOnlyTool(%q) = true, want false; a destructive segment must win over a read-only one", name)
		}
		// Sanity: the fixture really does match both vocabularies, so it exercises the overlap.
		if !InvokesDestructiveOperation(tm) {
			t.Errorf("InvokesDestructiveOperation(%q) = false; fixture no longer exercises the read-only/destructive overlap", name)
		}
	}
}

package mcptransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	detmcptransport "github.com/praetorian-inc/augustus/internal/detectors/mcptransport"
	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ---------------------------------------------------------------------------
// Non-corpus control servers. DVMCP ships ZERO authenticated servers, so it
// cannot validate this probe's headline capability at all — these stubs are the
// real proof. Each is a REAL MCP server (SDK handler behind httptest) so the
// full initialize / tools/list / tools/call path is exercised.
// ---------------------------------------------------------------------------

// authzServer is a stub MCP server that records the tools it was asked to run.
type authzServer struct {
	ts *httptest.Server
	// requireToken, when non-empty, is enforced at the HTTP layer.
	mu     sync.Mutex
	called []string
}

func (s *authzServer) calledTools() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.called...)
}

// newAuthzServer builds an MCP server with one read-only and one destructive
// tool. requireToken != "" makes it genuinely enforce authentication.
func newAuthzServer(t *testing.T, requireToken string) *authzServer {
	t.Helper()
	as := &authzServer{}

	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "authz-stub", Version: "1"}, nil)
	record := func(name string) {
		as.mu.Lock()
		as.called = append(as.called, name)
		as.mu.Unlock()
	}
	tru := true
	srv.AddTool(&mcpsdk.Tool{
		Name:        "get_status",
		Description: "Return service status",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		record("get_status")
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "status: ok"}}}, nil
	})
	srv.AddTool(&mcpsdk.Tool{
		Name:        "wipe_everything",
		Description: "Destroy all records",
		Annotations: &mcpsdk.ToolAnnotations{DestructiveHint: &tru},
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
		record("wipe_everything")
		return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "wiped"}}}, nil
	})

	h := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return srv }, nil)
	as.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requireToken != "" && r.Header.Get("Authorization") != "Bearer "+requireToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(as.ts.Close)
	return as
}

// authzGen is a target generator implementing MCPEndpoint, CredentialReporter and
// ToolInvoker.
//
// The AUTHENTICATED half (ToolInvoker) is an in-process fake: the probe only
// needs to know whether the operator's own session can exercise the target, and
// a fake states that precisely. The ANONYMOUS half is the real httptest server,
// because that is the behaviour under test.
type authzGen struct {
	endpoint    string
	transport   string
	credHeaders []string
	authTools   []map[string]any
	authErr     error
}

func (g authzGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (g authzGen) ClearHistory()       {}
func (g authzGen) Name() string        { return "authzGen" }
func (g authzGen) Description() string { return "authzGen" }
func (g authzGen) EndpointURL() string { return g.endpoint }
func (g authzGen) Transport() string   { return g.transport }
func (g authzGen) ProxyURL() *url.URL  { return nil }
func (g authzGen) HTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func (g authzGen) AnonymousHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
func (g authzGen) ConfiguredCredentialHeaders() []string { return g.credHeaders }

func (g authzGen) ListTools(context.Context) ([]map[string]any, error) {
	if g.authErr != nil {
		return nil, g.authErr
	}
	if g.authTools != nil {
		return g.authTools, nil
	}
	return []map[string]any{{"name": "get_status"}, {"name": "wipe_everything"}}, nil
}

func (g authzGen) CallTool(context.Context, string, map[string]any) (types.ToolResult, error) {
	return types.ToolResult{Text: "status: ok"}, nil
}

// bareGen implements neither MCPEndpoint nor CredentialReporter.
type bareGen struct{}

func (bareGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (bareGen) ClearHistory()       {}
func (bareGen) Name() string        { return "bareGen" }
func (bareGen) Description() string { return "bareGen" }

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func newUnauthProbe(t *testing.T, cfg registry.Config) *UnauthenticatedAccess {
	t.Helper()
	p, err := NewUnauthenticatedAccess(cfg)
	if err != nil {
		t.Fatalf("NewUnauthenticatedAccess: %v", err)
	}
	return p.(*UnauthenticatedAccess)
}

// scoreByClass runs the REAL detector over the probe's attempts and returns the
// max score per class. Importing the production detector (rather than
// re-implementing its rules here) is what makes these tests fail if the scoring
// contract ever breaks.
func scoreByClass(t *testing.T, attempts []*attempt.Attempt) map[string]float64 {
	t.Helper()
	det, err := detmcptransport.NewUnauthenticatedAccessDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewUnauthenticatedAccessDetector: %v", err)
	}
	out := map[string]float64{}
	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthClass)
		class, _ := raw.(string)
		// Register the class even when it scores 0.0, so a caller can distinguish
		// "this class was tested and came back clean" from "this class was never
		// tested at all". Collapsing those two would let a missing attempt pass as
		// a safe result.
		if _, seen := out[class]; !seen {
			out[class] = 0.0
		}
		scores, err := det.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		for _, s := range scores {
			if s > out[class] {
				out[class] = s
			}
		}
	}
	return out
}

func maxScore(scores map[string]float64) float64 {
	max := 0.0
	for _, s := range scores {
		if s > max {
			max = s
		}
	}
	return max
}

// ---------------------------------------------------------------------------
// MANDATORY non-corpus controls
// ---------------------------------------------------------------------------

// CONTROL 1 — a stub that genuinely enforces authentication and rejects the
// anonymous session must NOT fire.
func TestUnauthenticatedAccess_EnforcingServerDoesNotFire(t *testing.T) {
	as := newAuthzServer(t, "goodtoken")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	scores := scoreByClass(t, attempts)
	if got := maxScore(scores); got >= 0.5 {
		t.Errorf("enforcing server scored %v (scores=%v), want < 0.5 — must NOT fire", got, scores)
	}
	// The refusal must be recorded as evidence, not silently dropped.
	if len(attempts) == 0 {
		t.Fatal("Probe returned no attempts; the anonymous refusal must be recorded as evidence")
	}
}

// CONTROL 2 — a stub that is unauthenticated WHILE credentials were configured
// MUST fire. This is the headline capability and nothing in DVMCP exercises it.
func TestUnauthenticatedAccess_OpenServerWithCredentialsFires(t *testing.T) {
	as := newAuthzServer(t, "") // no auth enforced
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	scores := scoreByClass(t, attempts)
	if got := maxScore(scores); got < 0.5 {
		t.Errorf("open server with credentials configured scored %v (scores=%v), want >= 0.5 — MUST fire", got, scores)
	}
	if _, ok := scores[mcpprobe.AuthClassAnonEnumeration]; !ok {
		t.Errorf("no %q attempt recorded (classes=%v)", mcpprobe.AuthClassAnonEnumeration, scores)
	}
	if _, ok := scores[mcpprobe.AuthClassAnonInvocation]; !ok {
		t.Errorf("no %q attempt recorded (classes=%v)", mcpprobe.AuthClassAnonInvocation, scores)
	}
}

// CONTROL 3 — a run configured with NO credentials at all must NOT fire, and must
// skip with a stated reason rather than report SAFE.
func TestUnauthenticatedAccess_NoCredentialsSkips(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: nil}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Probe returned %d attempts with no credentials configured, want 0 (explicit skip)", len(attempts))
	}
	if got := maxScore(scoreByClass(t, attempts)); got != 0.0 {
		t.Errorf("no-credentials run scored %v, want 0.0", got)
	}
}

// CONTROL 4 — a loopback target with no effective auth is inconclusive, not
// vulnerable. httptest binds 127.0.0.1, so this is the natural loopback case.
func TestUnauthenticatedAccess_LoopbackIsInconclusiveNotVulnerable(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, a := range attempts {
		raw, _ := a.GetMetadata(mcpprobe.MetaAuthTargetClass)
		if tc, _ := raw.(string); tc != "loopback" {
			t.Errorf("attempt target class = %q, want %q (httptest binds 127.0.0.1)", tc, "loopback")
		}
	}
	if got := maxScore(scoreByClass(t, attempts)); got >= 1.0 {
		t.Errorf("loopback target scored %v, want < 1.0 (inconclusive, not vulnerable)", got)
	}
}

// ---------------------------------------------------------------------------
// Fail-loud and safety behaviour
// ---------------------------------------------------------------------------

// A target with no MCPEndpoint surface cannot be assessed. It must fail loudly
// rather than return a clean-looking empty result — a silent false negative is
// the worst outcome for a scanner.
func TestUnauthenticatedAccess_NoEndpointInterfaceFailsLoud(t *testing.T) {
	p := newUnauthProbe(t, registry.Config{})
	if _, err := p.Probe(context.Background(), bareGen{}); err == nil {
		t.Fatal("Probe returned nil error for a target without types.MCPEndpoint, want a loud failure")
	}
}

// A target that cannot report whether credentials were configured cannot support
// the differential, so the probe must skip with a stated reason.
func TestUnauthenticatedAccess_NoCredentialReporterSkips(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	// endpointGen (from originvalidation_test.go) implements MCPEndpoint but not
	// CredentialReporter.
	attempts, err := p.Probe(context.Background(), endpointGen{url: as.ts.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Probe returned %d attempts for a target that cannot report credentials, want 0 (skip)", len(attempts))
	}
}

// The invocation proof must only ever call a read-only tool. Enumeration already
// carries the headline finding, so this probe never needs to mutate a target's
// state, and calling an annotated-destructive tool would be unacceptable against
// production infrastructure.
func TestUnauthenticatedAccess_NeverInvokesDestructiveTool(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	if _, err := p.Probe(context.Background(), gen); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, name := range as.calledTools() {
		if name == "wipe_everything" {
			t.Errorf("probe invoked the destructive tool %q; only read-only tools may be invoked", name)
		}
	}
}

// The destructive gate must be honourable via tool_denylist too.
func TestUnauthenticatedAccess_HonoursToolDenylist(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{"tool_denylist": []string{"get_status"}})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, name := range as.calledTools() {
		if name == "get_status" {
			t.Errorf("probe invoked denylisted tool %q", name)
		}
	}
	// Enumeration must still be reported — it carries the headline finding.
	if _, ok := scoreByClass(t, attempts)[mcpprobe.AuthClassAnonEnumeration]; !ok {
		t.Error("enumeration attempt missing; it must be reported even when no tool may be invoked")
	}
}

// Anonymous success with a FAILED authenticated baseline is not trustworthy
// evidence: the endpoint may be answering everything the same way.
func TestUnauthenticatedAccess_AuthBaselineFailureIsInconclusive(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{
		endpoint: as.ts.URL, transport: "http",
		credHeaders: []string{"Authorization"},
		authErr:     errors.New("authenticated session failed"),
	}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	scores := scoreByClass(t, attempts)
	if got := maxScore(scores); got >= 1.0 {
		t.Errorf("anonymous success without an authenticated baseline scored %v, want < 1.0", got)
	}
}

// Credential header NAMES must reach the evidence so a reviewer knows which
// boundary was bypassed; values must never be recorded anywhere.
func TestUnauthenticatedAccess_RecordsCredentialHeaderNames(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization", "X-Api-Key"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts")
	}
	raw, ok := attempts[0].GetMetadata(mcpprobe.MetaAuthCredentialHeaders)
	if !ok {
		t.Fatal("attempt does not record the configured credential header names")
	}
	got, _ := raw.(string)
	if !strings.Contains(got, "Authorization") || !strings.Contains(got, "X-Api-Key") {
		t.Errorf("credential headers metadata = %q, want both configured names", got)
	}
}

// A non-HTTP endpoint is out of scope for a transport-layer probe: skip quietly
// with no error, matching the sibling probes.
func TestUnauthenticatedAccess_NonHTTPEndpointSkips(t *testing.T) {
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: "stdio:///usr/bin/server", transport: "stdio", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("Probe returned %d attempts for a non-HTTP endpoint, want 0", len(attempts))
	}
}

// The authenticated baseline must be recorded and must never itself be a finding.
func TestUnauthenticatedAccess_BaselineRecordedAndNeverFires(t *testing.T) {
	as := newAuthzServer(t, "")
	p := newUnauthProbe(t, registry.Config{})
	gen := authzGen{endpoint: as.ts.URL, transport: "http", credHeaders: []string{"Authorization"}}

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	scores := scoreByClass(t, attempts)
	got, ok := scores[mcpprobe.AuthClassAuthBaseline]
	if !ok {
		t.Fatalf("no authenticated-baseline attempt recorded (classes=%v)", scores)
	}
	if got != 0.0 {
		t.Errorf("auth baseline scored %v, want 0.0 (informational control)", got)
	}
}

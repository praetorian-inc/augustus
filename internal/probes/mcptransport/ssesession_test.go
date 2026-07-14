package mcptransport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// sseTestServer wraps httptest so a table-test can inject session-id
// generation and POST-accept behaviour.
type sseTestServer struct {
	*httptest.Server
	// nextID returns the session id for the next SSE connection.
	nextID func(idx int) string
	// acceptPost decides whether a POST is 200 (accepted) or 401 (rejected).
	// Receives the session_id from the URL.
	acceptPost func(id string) bool

	sseCount  atomic.Int32
	postCount atomic.Int32
}

func newSSETestServer(t *testing.T, nextID func(int) string, acceptPost func(string) bool) *sseTestServer {
	t.Helper()
	s := &sseTestServer{nextID: nextID, acceptPost: acceptPost}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/sse"):
			idx := int(s.sseCount.Add(1)) - 1
			id := s.nextID(idx)
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /messages/?session_id=%s\n\n", id)
			if flusher != nil {
				flusher.Flush()
			}
			// Keep the connection open a bit so the probe considers the
			// stream "served," but let it close on its own soon after.
			<-r.Context().Done()
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/messages"):
			s.postCount.Add(1)
			id := r.URL.Query().Get("session_id")
			if s.acceptPost(id) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			} else {
				http.Error(w, "unknown session", http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	return s
}

func newSSESessionProbe(t *testing.T, cfg registry.Config) *SSESessionHijack {
	t.Helper()
	p, err := NewSSESessionHijack(cfg)
	if err != nil {
		t.Fatalf("NewSSESessionHijack: %v", err)
	}
	return p.(*SSESessionHijack)
}

// findingsBySSEClass filters to non-zero scores using the same detector
// logic the real detector applies (baseline + unknown-id-rejects excluded).
func findingsBySSEClass(attempts []*attempt.Attempt) map[string]bool {
	fired := map[string]bool{}
	for _, a := range attempts {
		raw, _ := a.GetMetadata(attempt.MetadataKeySSESessionClass)
		class, _ := raw.(string)
		if class == "baseline" || class == "unknown-id-rejects" {
			continue
		}
		if metaBool(a, attempt.MetadataKeySSESessionAccepted) {
			fired[class] = true
		}
	}
	return fired
}

// TestSSESession_HardenedServer: strong UUID-shaped ids + POST accepted only
// for the one specific id we're using, and only after we HELD the stream (a
// TCP-bound server). Expected: zero findings.
func TestSSESession_HardenedServer(t *testing.T) {
	// Real UUID-like ids: 32 hex-char per sample, all unique.
	pool := []string{
		"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
		"ce5b8c7c5f9c47c988c14c5b21b8b2f5",
		"7d3a1c4e0e2b48e5b7d9a1e2f3d4c5b6",
		"1122334455667788aabbccddeeff0011",
		"deadbeefcafefeed0123456789abcdef",
		"fedcba9876543210deadbeefcafefeed",
	}
	nextID := func(i int) string { return pool[i%len(pool)] }

	// Reject cross-connection replay: only accept a POST if we know we
	// haven't already seen this connection close. For test purposes reject
	// ALL POSTs — a well-behaved server binds sessions to their TCP conn.
	acceptPost := func(id string) bool { return false }

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if len(fired) != 0 {
		t.Errorf("hardened server should produce no findings, got %v", fired)
	}
}

// TestSSESession_NoLiveSessionInMetadata: after a sample handshake, the
// live session ID must NEVER appear in any attempt's metadata or output.
// Only the fingerprint and redacted URL should be visible. Fixes
// CodeRabbit finding #4.
func TestSSESession_NoLiveSessionInMetadata(t *testing.T) {
	sessionID := "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d"
	srv := newSSETestServer(t, func(int) string { return sessionID }, func(string) bool { return false })
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, a := range attempts {
		// Attempt outputs
		for _, out := range a.Outputs {
			if strings.Contains(out, sessionID) {
				t.Errorf("live session id %q leaked into attempt output %q", sessionID, out)
			}
		}
		// Attempt metadata values
		for k, v := range a.Metadata {
			s, ok := v.(string)
			if !ok {
				continue
			}
			if strings.Contains(s, sessionID) {
				t.Errorf("live session id %q leaked into metadata %q=%q", sessionID, k, s)
			}
		}
	}
}

// TestSSESession_NotTCPBound: strong ids but the server accepts POSTs from
// any TCP connection (rejects fabricated ids, accepts real ones). Expected:
// session-not-tcp-bound + session-post-close-alive fire.
func TestSSESession_NotTCPBound(t *testing.T) {
	pool := []string{
		"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
		"ce5b8c7c5f9c47c988c14c5b21b8b2f5",
		"7d3a1c4e0e2b48e5b7d9a1e2f3d4c5b6",
		"1122334455667788aabbccddeeff0011",
	}
	seen := map[string]bool{}
	for _, id := range pool {
		seen[id] = true
	}
	nextID := func(i int) string { return pool[i%len(pool)] }
	acceptPost := func(id string) bool { return seen[id] } // real ids accepted regardless of conn

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassNotTCPBound)] {
		t.Errorf("session-not-tcp-bound should fire; fired=%v", fired)
	}
	if !fired[string(sseClassPostCloseAlive)] {
		t.Errorf("session-post-close-alive should fire; fired=%v", fired)
	}
}

// TestSSESession_ControlSuppresses: a server that accepts ANY id (broken
// session handling entirely) triggers the unknown-id-rejects control's
// suppression path; the replay findings must NOT fire even though the raw
// POSTs succeed.
func TestSSESession_ControlSuppresses(t *testing.T) {
	pool := []string{
		"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
		"ce5b8c7c5f9c47c988c14c5b21b8b2f5",
		"7d3a1c4e0e2b48e5b7d9a1e2f3d4c5b6",
		"1122334455667788aabbccddeeff0011",
	}
	nextID := func(i int) string { return pool[i%len(pool)] }
	acceptPost := func(id string) bool { return true } // accepts everything

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if fired[string(sseClassNotTCPBound)] {
		t.Errorf("session-not-tcp-bound should be suppressed when server accepts any id; fired=%v", fired)
	}
	if fired[string(sseClassPostCloseAlive)] {
		t.Errorf("session-post-close-alive should be suppressed when server accepts any id; fired=%v", fired)
	}
}

// proxiedGen is an endpointGen that reports a non-nil ProxyURL so tests can
// exercise the connection-lifetime-finding suppression path.
type proxiedGen struct {
	endpointGen
	proxy string
}

func (g proxiedGen) ProxyURL() *url.URL {
	u, _ := url.Parse(g.proxy)
	return u
}

// TestSSESession_ProxiedReplaysScoreInconclusive: through a proxy the two
// connection-lifetime replay classes MUST NOT ship as VULN (proxy would
// generate that signal for a hardened target too) but MUST NOT ship as
// SAFE either (hiding a real vuln under proxy noise). Correct behaviour:
// both attempts carry MetadataKeyInconclusive, and the detector emits
// InconclusiveScore (0.5) — visible to the reviewer, not a green
// verdict. Regression guard for Mauro B2.
func TestSSESession_ProxiedReplaysScoreInconclusive(t *testing.T) {
	pool := []string{
		"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d",
		"ce5b8c7c5f9c47c988c14c5b21b8b2f5",
		"7d3a1c4e0e2b48e5b7d9a1e2f3d4c5b6",
		"1122334455667788aabbccddeeff0011",
	}
	seen := map[string]bool{}
	for _, id := range pool {
		seen[id] = true
	}
	nextID := func(i int) string { return pool[i%len(pool)] }
	acceptPost := func(id string) bool { return seen[id] }

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	gen := proxiedGen{endpointGen: endpointGen{url: srv.URL + "/sse", transport: "sse"}, proxy: "http://127.0.0.1:9999"}
	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// The two replay classes must be marked inconclusive; the ID-space
	// classes are proxy-immune and stay unaffected.
	replayClasses := map[string]bool{
		string(sseClassNotTCPBound):    false,
		string(sseClassPostCloseAlive): false,
	}
	for _, a := range attempts {
		raw, _ := a.GetMetadata(attempt.MetadataKeySSESessionClass)
		cls, _ := raw.(string)
		if _, ok := replayClasses[cls]; !ok {
			continue
		}
		if !metaBool(a, attempt.MetadataKeyInconclusive) {
			t.Errorf("class %s must be marked inconclusive under proxy", cls)
		}
		if !metaBool(a, attempt.MetadataKeySSESessionAccepted) {
			t.Errorf("class %s: accepted must remain the honest observation (true), not suppressed to false", cls)
		}
		replayClasses[cls] = true
	}
	for cls, seen := range replayClasses {
		if !seen {
			t.Errorf("class %s attempt was not emitted at all", cls)
		}
	}
}

// TestSSESession_SkipsNonSSETransport: probe returns nothing for a non-SSE
// transport.
func TestSSESession_SkipsNonSSETransport(t *testing.T) {
	p := newSSESessionProbe(t, registry.Config{"endpoint": "http://x"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: "http://x", transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for non-SSE transport, got %d", len(attempts))
	}
}

// TestReadEndpointEvent_KeepaliveDoesNotLeakState: a data-less keepalive
// frame like `event: ping\n\n` must not leak `eventName` into the next
// frame's context (Gemini review LAB-4462). Feeds a keepalive followed by
// a `data: /messages/?session_id=abc` frame with no `event:` and expects
// NO match (endpoint requires event=endpoint), then feeds a proper endpoint
// frame afterwards and expects a match.
func TestReadEndpointEvent_KeepaliveDoesNotLeakState(t *testing.T) {
	stream := strings.NewReader(
		"event: ping\n\n" + // keepalive: eventName=ping, no data
			"data: /messages/?session_id=stale\n\n" + // orphan data — must NOT match endpoint
			"event: endpoint\ndata: /messages/?session_id=real\n\n", // real endpoint frame
	)
	id, path, err := readEndpointEvent(stream, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("readEndpointEvent: %v", err)
	}
	if id != "real" {
		t.Errorf("id=%q, want 'real' (state leaked from ping keepalive)", id)
	}
	if !strings.Contains(path, "session_id=real") {
		t.Errorf("path=%q, want session_id=real", path)
	}
}

// TestResolvePostURL_RefusesOffHost: a malicious MCP that returns an
// absolute URL pointing at cloud metadata or an internal host must be
// refused. Enforcing scheme+host equality closes an SSRF primitive
// (Gemini review LAB-4462).
func TestResolvePostURL_RefusesOffHost(t *testing.T) {
	tests := []struct {
		name         string
		base         string
		endpointPath string
		wantErr      bool
	}{
		{"relative path — allowed", "http://127.0.0.1:9003/sse", "/messages/?session_id=x", false},
		{"same-host absolute — allowed", "http://127.0.0.1:9003/sse", "http://127.0.0.1:9003/messages/?session_id=x", false},
		{"IMDS absolute — refused", "http://127.0.0.1:9003/sse", "http://169.254.169.254/latest/meta-data/", true},
		{"cross-host absolute — refused", "http://127.0.0.1:9003/sse", "http://internal.corp/admin", true},
		{"scheme-downgrade — refused", "https://mcp.example.com/sse", "http://mcp.example.com/messages/", true},
		{"different port — refused", "http://127.0.0.1:9003/sse", "http://127.0.0.1:22/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolvePostURL(tt.base, tt.endpointPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolvePostURL(%q, %q) err=%v, wantErr=%v", tt.base, tt.endpointPath, err, tt.wantErr)
			}
		})
	}
}

// TestExtractSessionID covers the parser directly so we don't rely on live
// servers to hit each branch.
func TestExtractSessionID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/messages/?session_id=abc123", "abc123"},
		{"/messages/?session_id=abc123&foo=bar", "abc123"},
		{"/messages/?foo=bar&session_id=abc123", "abc123"},
		{"/messages/", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractSessionID(tt.in)
		if got != tt.want {
			t.Errorf("extractSessionID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestServerAcceptedPOST covers the JSON-RPC-aware response
// classification helper introduced for CodeRabbit finding #3.
func TestServerAcceptedPOST(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"202 empty body (FastMCP happy path)", 202, "", true},
		{"200 empty body", 200, "", true},
		{"200 jsonrpc result", 200, `{"jsonrpc":"2.0","id":1,"result":{}}`, true},
		{"200 jsonrpc error", 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"session expired"}}`, false},
		{"200 non-jsonrpc body", 200, `{"hello":"world"}`, false},
		{"400 rejected", 400, "unknown session", false},
		{"404 rejected", 404, "", false},
		{"500 server error", 500, "", false},
		{"200 malformed json", 200, "not json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serverAcceptedPOST(tt.status, tt.body)
			if got != tt.want {
				t.Errorf("serverAcceptedPOST(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}

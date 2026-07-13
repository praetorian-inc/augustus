package toolsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
			fmt.Fprintf(w, "event: endpoint\ndata: /messages/?session_id=%s\n\n", id)
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

// TestSSESession_ShortIDs: ids too short (< 16 chars). Expected: session-id-
// short fires; nothing else.
func TestSSESession_ShortIDs(t *testing.T) {
	nextID := func(i int) string { return strconv.Itoa(1000 + i) } // 4 chars
	acceptPost := func(id string) bool { return false }

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassShort)] {
		t.Errorf("session-id-short should fire on 4-char ids; fired=%v", fired)
	}
}

// TestSSESession_GuessableShape_AllDigits: a session id that is entirely
// decimal digits (counter, unix timestamp, sequence) is shape-guessable
// and must fire session-id-guessable-shape from a SINGLE sample.
func TestSSESession_GuessableShape_AllDigits(t *testing.T) {
	nextID := func(i int) string { return "1735689600" } // unix ts
	srv := newSSETestServer(t, nextID, func(string) bool { return false })
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassGuessableShape)] {
		t.Errorf("session-id-guessable-shape should fire on all-digits id; fired=%v", fired)
	}
}

// TestSSESession_LowDiversity: a session id whose unique-char count is
// tiny relative to its length (repetitive or narrow alphabet) fires
// session-id-low-diversity — a pure shape observation, no RNG claim.
func TestSSESession_LowDiversity(t *testing.T) {
	// 32 chars, 3 unique letters — diversity 3/32 ≈ 0.09, well below 0.25.
	nextID := func(i int) string { return "aaaaaaaaaabbbbbbbbbbccccccccccaa" }
	srv := newSSETestServer(t, nextID, func(string) bool { return false })
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassLowDiversity)] {
		t.Errorf("session-id-low-diversity should fire on repetitive id; fired=%v", fired)
	}
}

// TestSSESession_HighDiversityUUIDPasses: a real UUID4-shape id must NOT
// trip low-diversity or guessable-shape — 32 hex chars use 16 distinct
// symbols (diversity 0.5) and are neither all-digits nor all-alpha.
func TestSSESession_HighDiversityUUIDPasses(t *testing.T) {
	nextID := func(i int) string { return "9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d" }
	srv := newSSETestServer(t, nextID, func(string) bool { return false })
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse"})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if fired[string(sseClassLowDiversity)] {
		t.Errorf("session-id-low-diversity must NOT fire on UUID4-shape id; fired=%v", fired)
	}
	if fired[string(sseClassGuessableShape)] {
		t.Errorf("session-id-guessable-shape must NOT fire on UUID4-shape id; fired=%v", fired)
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

// TestCharDiversity spot-checks the diversity helper.
func TestCharDiversity(t *testing.T) {
	tests := []struct {
		in  string
		min float64
		max float64
	}{
		{"aaaa", 0.24, 0.26},                             // 1/4
		{"abcd", 0.99, 1.01},                             // 4/4
		{"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d", 0.20, 0.60}, // hex UUID ~0.5
		{"aaaaaaaaaabbbbbbbbbbccccccccccaa", 0.08, 0.10}, // 3/32
	}
	for _, tt := range tests {
		got := charDiversity(tt.in)
		if got < tt.min || got > tt.max {
			t.Errorf("charDiversity(%q) = %.3f, want in [%.2f, %.2f]", tt.in, got, tt.min, tt.max)
		}
	}
}

// TestGuessableShape covers the shape-sniff.
func TestGuessableShape(t *testing.T) {
	positive := []string{
		"1735689600", // unix timestamp
		"1234567890", // counter-like
		"abcdefghij", // pure lowercase, ≥ 4 chars
	}
	for _, id := range positive {
		if _, ok := guessableShape(id); !ok {
			t.Errorf("guessableShape(%q) should have fired", id)
		}
	}
	negative := []string{
		"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d", // UUID4 hex
		"abc123def456",                     // mixed alphanum
		"",                                 // empty
		"abc",                              // too short for lower-alpha check
	}
	for _, id := range negative {
		if _, ok := guessableShape(id); ok {
			t.Errorf("guessableShape(%q) should NOT have fired", id)
		}
	}
}

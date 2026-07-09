package toolsec

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

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

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": len(pool)})
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

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": 6})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassShort)] {
		t.Errorf("session-id-short should fire on 4-char ids; fired=%v", fired)
	}
}

// TestSSESession_CommonPrefix: ids share a long prefix (partially
// deterministic — timestamp + counter shape). Expected: session-id-common-
// prefix fires.
func TestSSESession_CommonPrefix(t *testing.T) {
	prefix := "prefix-shared-12345678-"
	nextID := func(i int) string { return prefix + fmt.Sprintf("%08x", i) }
	acceptPost := func(id string) bool { return false }

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": 6})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassCommonPrefix)] {
		t.Errorf("session-id-common-prefix should fire on shared-prefix ids; fired=%v", fired)
	}
}

// TestSSESession_Collision: two samples yield the same id. Expected:
// session-id-collision fires.
func TestSSESession_Collision(t *testing.T) {
	nextID := func(i int) string {
		if i%2 == 0 {
			return "collidingsessionid00000000000001"
		}
		return "collidingsessionid00000000000002"
	}
	acceptPost := func(id string) bool { return false }

	srv := newSSETestServer(t, nextID, acceptPost)
	defer srv.Close()

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": 6})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL + "/sse", transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsBySSEClass(attempts)
	if !fired[string(sseClassCollision)] {
		t.Errorf("session-id-collision should fire on duplicated ids; fired=%v", fired)
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

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": len(pool)})
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

	p := newSSESessionProbe(t, registry.Config{"endpoint": srv.URL + "/sse", "sample_count": len(pool)})
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

// TestShannonBitsPerChar spot-checks the entropy helper — narrow character
// sets score low, high-diversity strings score higher.
func TestShannonBitsPerChar(t *testing.T) {
	tests := []struct {
		in    string
		minOK float64 // want ≥ this
		maxOK float64 // want ≤ this
	}{
		{"aaaa", 0.0, 0.5},                                                   // one char → 0 bits
		{"abcd", 1.5, 2.5},                                                   // uniform 4 → 2 bits
		{"9b1deb4d3b7d4bad9bdd2b0d7b3dcb6dce5b8c7c5f9c47c988c14c5b21b8b2f5", 3.5, 4.5}, // hex → ~3.9
	}
	for _, tt := range tests {
		got := shannonBitsPerChar(tt.in)
		if got < tt.minOK || got > tt.maxOK {
			t.Errorf("shannonBitsPerChar(%q) = %.3f, want in [%.2f, %.2f]", tt.in, got, tt.minOK, tt.maxOK)
		}
	}
}

// TestLongestCommonPrefix covers the small helper.
func TestLongestCommonPrefix(t *testing.T) {
	if got := longestCommonPrefix([]string{"abcxyz", "abcpqr", "abclmn"}); got != "abc" {
		t.Errorf("got %q, want abc", got)
	}
	if got := longestCommonPrefix([]string{"a", "b"}); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

package toolsec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// endpointGen is a minimal generator satisfying types.MCPEndpoint so the probe
// can resolve the URL without a real MCP session.
type endpointGen struct {
	url       string
	transport string
}

func (g endpointGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (g endpointGen) ClearHistory()       {}
func (g endpointGen) Name() string        { return "endpointGen" }
func (g endpointGen) Description() string { return "endpointGen" }
func (g endpointGen) EndpointURL() string { return g.url }
func (g endpointGen) Transport() string   { return g.transport }

// HTTPClient returns a plain client. Tests that need a proxy-aware client can
// override this by using a different generator stub.
func (g endpointGen) HTTPClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second}
}

// ProxyURL returns nil — tests that need to simulate a proxy in path use a
// separate stub (see proxiedGen below).
func (g endpointGen) ProxyURL() *url.URL { return nil }

func newDNSRebindProbe(t *testing.T, cfg registry.Config) *DNSRebinding {
	t.Helper()
	p, err := NewDNSRebinding(cfg)
	if err != nil {
		t.Fatalf("NewDNSRebinding: %v", err)
	}
	return p.(*DNSRebinding)
}

// initializeOK is a well-formed MCP initialize response body.
const initializeOK = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"srv","version":"1"},"capabilities":{}}}`

// vulnServer answers any MCP initialize regardless of the request headers —
// the shape of every unpatched MCP HTTP server as originally shipped.
func vulnServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(initializeOK))
	}))
}

// strictAllowlistServer implements the shape of the MCP TypeScript SDK 1.24
// defence: strict-string Origin/Host allowlist, missing Origin passes.
func strictAllowlistServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			// Only allow a canonical localhost Origin. Everything else — 403.
			if origin != "http://localhost" && origin != "http://127.0.0.1" {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
		}
		if r.Host != srv.Listener.Addr().String() {
			http.Error(w, "host not allowed", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "http://localhost")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(initializeOK))
	})
	srv.Start()
	return srv
}

// substringOriginServer imitates a "$2 WAF" — an Origin validator that just
// looks for known-bad substrings. Anything not containing "evil", "attacker",
// "hack", or "malicious" passes. This is the shape our old probe was tuned to
// hit with hardcoded "evil.example.com" strings; the redesigned probe must
// still catch it because randomised RFC 2606 domains defeat the substring
// check.
func substringOriginServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.ToLower(r.Header.Get("Origin"))
		for _, tok := range []string{"evil", "attacker", "hack", "malicious"} {
			if strings.Contains(origin, tok) {
				http.Error(w, "blocked", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(initializeOK))
	}))
}

// corsReflectServer reflects the request Origin in Access-Control-Allow-Origin
// and sets Allow-Credentials: true — the FastAPI-style misconfiguration that
// turns a rebinding foothold into a credentialed cross-origin read.
func corsReflectServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(initializeOK))
	}))
}

// findingsByClass runs the detector-side check and returns which bypass
// classes fired at least one 1.0 score.
func findingsByClass(attempts []*attempt.Attempt) map[string]bool {
	det := &dnsRebindDetectorStub{}
	fired := map[string]bool{}
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyDNSRebindClass)
		classStr, _ := class.(string)
		for _, s := range det.detect(a) {
			if s == 1.0 {
				fired[classStr] = true
			}
		}
	}
	return fired
}

// TestDNSRebinding_VulnerableServer: a server with no validation is caught on
// every non-baseline class.
func TestDNSRebinding_VulnerableServer(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)

	// httptest binds 127.0.0.1:PORT, so swapCase is a no-op on the host and
	// the case-variant class is (correctly) skipped — see the
	// TestDNSRebinding_CaseVariantSkippedOnNumericHost test below.
	wantClasses := []string{
		string(classExternalOrigin),
		string(classNullOrigin),
		string(classExtensionOrigin),
		string(classLocalhostLookalike),
		string(classUnexpectedHost),
	}
	for _, c := range wantClasses {
		if !fired[c] {
			t.Errorf("class %q should have fired on the fully-vulnerable server (fired=%v)", c, fired)
		}
	}
	if fired[string(classBaseline)] {
		t.Errorf("baseline should never fire as a finding")
	}
	if fired[string(classCaseVariant)] {
		t.Errorf("case-variant must NOT fire on an all-numeric host (would be an FP)")
	}
}

// TestDNSRebinding_CaseVariantSkippedOnNumericHost: on hosts with no ASCII
// letters (127.0.0.1:X, [::1]:X, cloud IP literals) swapCase is a no-op, so
// the probe would otherwise send the target's OWN canonical Origin and a
// hardened allowlist server would legitimately accept it — false positive.
// This locks in the skip. Regression guard for Claude review LAB-4462.
func TestDNSRebinding_CaseVariantSkippedOnNumericHost(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// Look for any attempt whose class is case-variant.
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyDNSRebindClass)
		if !ok {
			continue
		}
		if s, _ := raw.(string); s == string(classCaseVariant) {
			t.Errorf("case-variant attempt should be skipped on numeric host; got attempt %v", a.Prompt)
		}
	}
}

// TestDNSRebinding_StrictAllowlistNotFlagged: a strict-allowlist server passes
// only the baseline (no-Origin, informational) and nothing fires.
func TestDNSRebinding_StrictAllowlistNotFlagged(t *testing.T) {
	srv := strictAllowlistServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if len(fired) != 0 {
		t.Errorf("strict allowlist server should produce no findings, got %v", fired)
	}

	// The baseline attempt must have recorded acceptance so the sweep isn't
	// reported as inconclusive.
	base := findAttemptByClass(attempts, classBaseline)
	if base == nil {
		t.Fatal("expected a baseline attempt")
	}
	if !metaBool(base, attempt.MetadataKeyDNSRebindAccepted) {
		t.Errorf("baseline (no Origin) should be accepted by a spec-compliant server")
	}
}

// TestDNSRebinding_DefeatsSubstringWAF: a substring-blocklist "WAF" that would
// have caught the old hardcoded payloads is defeated by the randomised RFC
// 2606 payloads, and the probe still fires external-origin.
func TestDNSRebinding_DefeatsSubstringWAF(t *testing.T) {
	srv := substringOriginServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if !fired[string(classExternalOrigin)] {
		t.Errorf("external-origin bypass should fire against a substring-blocklist server; fired=%v", fired)
	}

	// Confirm that none of the payloads we sent contained a blocklist token.
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyDNSRebindOrigin)
		if !ok {
			continue
		}
		o, _ := raw.(string)
		for _, tok := range []string{"evil", "attacker", "hack", "malicious"} {
			if strings.Contains(strings.ToLower(o), tok) {
				t.Errorf("payload %q contains blocklist token %q — defeats the point of the probe", o, tok)
			}
		}
	}
}

// TestDNSRebinding_CORSReflectionWithCredsFired: a server that reflects the
// Origin and sets Allow-Credentials must fire the cors-reflect-creds class.
func TestDNSRebinding_CORSReflectionWithCredsFired(t *testing.T) {
	srv := corsReflectServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if !fired[string(classCORSReflectCreds)] {
		t.Errorf("cors-reflect-creds should fire when the server reflects Origin + Allow-Credentials; fired=%v", fired)
	}
}

// TestDNSRebinding_ResolvesEndpointFromGenerator: with no config endpoint the
// probe reads the URL off the generator via types.MCPEndpoint.
func TestDNSRebinding_ResolvesEndpointFromGenerator(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Errorf("expected attempts when generator supplies endpoint via MCPEndpoint")
	}
}

// TestDNSRebinding_SSEStreamServed: an SSE endpoint that starts serving
// text/event-stream to an attacker Origin is flagged. Origin/Host validation
// on the streaming half of legacy MCP is the same security boundary as on the
// streamable-HTTP POST half — both live before the transport handler.
func TestDNSRebinding_SSEStreamServed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve an event-stream for any GET, no Origin check — the FastMCP
		// SSE server default until DNS-rebind protections landed.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("event: message\ndata: {}\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer srv.Close()

	p := newDNSRebindProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if !fired[string(classExternalOrigin)] {
		t.Errorf("external-origin should fire on an SSE endpoint serving any Origin; fired=%v", fired)
	}
}

// TestDNSRebinding_SkipsWithoutEndpoint: no override and no MCPEndpoint yields
// nothing.
func TestDNSRebinding_SkipsWithoutEndpoint(t *testing.T) {
	p := newDNSRebindProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts with no endpoint, got %d", len(attempts))
	}
}

// TestServerProcessedInitialize covers the response-classification helper
// without needing a live server.
func TestServerProcessedInitialize(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        bool
	}{
		{"200 json-rpc result", 200, "application/json", `{"jsonrpc":"2.0","id":1,"result":{}}`, true},
		{"200 json-rpc error — server refused inside envelope, NOT accepted", 200, "application/json", `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}`, false},
		{"200 sse stream", 200, "text/event-stream", "event: message\ndata: {}\n", true},
		{"200 non-jsonrpc body", 200, "application/json", `{"hello":"world"}`, false},
		{"403 rejected", 403, "text/plain", "origin not allowed", false},
		{"200 empty body", 200, "application/json", "", false},
		{"200 malformed json", 200, "application/json", "not json", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serverProcessedInitialize(tt.status, tt.contentType, []byte(tt.body))
			if got != tt.want {
				t.Errorf("got %v, want %v (body=%q)", got, tt.want, tt.body)
			}
		})
	}
}

// findAttemptByClass returns the first attempt with the given class label, or
// nil.
func findAttemptByClass(attempts []*attempt.Attempt, class dnsRebindClass) *attempt.Attempt {
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyDNSRebindClass)
		if !ok {
			continue
		}
		s, _ := raw.(string)
		if s == string(class) {
			return a
		}
	}
	return nil
}

// dnsRebindDetectorStub reimplements the acceptance check locally so the
// probe test does not depend on the detector package.
type dnsRebindDetectorStub struct{}

func (dnsRebindDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, _ := a.GetMetadata(attempt.MetadataKeyDNSRebindClass)
	class, _ := raw.(string)
	if !metaBoolStub(a, attempt.MetadataKeyDNSRebindAccepted) || class == string(classBaseline) {
		return scores
	}
	if len(scores) == 0 {
		return []float64{1.0}
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores
}

func metaBoolStub(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

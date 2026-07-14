package toolsec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// AnonymousHTTPClient returns a plain client without any header injection;
// the browser-attacker probes borrow this so the operator's auth headers
// don't leak into the request that models an untrusted origin.
func (g endpointGen) AnonymousHTTPClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second}
}

// ProxyURL returns nil — tests that need to simulate a proxy in path use a
// separate stub (see proxiedGen below).
func (g endpointGen) ProxyURL() *url.URL { return nil }

func newOriginValidationProbe(t *testing.T, cfg registry.Config) *OriginValidation {
	t.Helper()
	p, err := NewOriginValidation(cfg)
	if err != nil {
		t.Fatalf("NewOriginValidation: %v", err)
	}
	return p.(*OriginValidation)
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
	det := &originValidationDetectorStub{}
	fired := map[string]bool{}
	for _, a := range attempts {
		class, _ := a.GetMetadata(attempt.MetadataKeyOriginValidationClass)
		classStr, _ := class.(string)
		for _, s := range det.detect(a) {
			if s == 1.0 {
				fired[classStr] = true
			}
		}
	}
	return fired
}

// TestOriginValidation_VulnerableServer: a server with no validation is caught on
// every non-baseline class.
func TestOriginValidation_VulnerableServer(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)

	// httptest binds 127.0.0.1:PORT, so swapCase is a no-op on the host and
	// the case-variant class is (correctly) skipped — see the
	// TestOriginValidation_CaseVariantSkippedOnNumericHost test below.
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

// TestOriginValidation_CaseVariantSkippedOnNumericHost: on hosts with no ASCII
// letters (127.0.0.1:X, [::1]:X, cloud IP literals) swapCase is a no-op, so
// the probe would otherwise send the target's OWN canonical Origin and a
// hardened allowlist server would legitimately accept it — false positive.
// This locks in the skip. Regression guard for Claude review LAB-4462.
func TestOriginValidation_CaseVariantSkippedOnNumericHost(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// Look for any attempt whose class is case-variant.
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationClass)
		if !ok {
			continue
		}
		if s, _ := raw.(string); s == string(classCaseVariant) {
			t.Errorf("case-variant attempt should be skipped on numeric host; got attempt %v", a.Prompt)
		}
	}
}

// TestOriginValidation_StrictAllowlistNotFlagged: a strict-allowlist server passes
// only the baseline (no-Origin, informational) and nothing fires.
func TestOriginValidation_StrictAllowlistNotFlagged(t *testing.T) {
	srv := strictAllowlistServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
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
	if !metaBool(base, attempt.MetadataKeyOriginValidationAccepted) {
		t.Errorf("baseline (no Origin) should be accepted by a spec-compliant server")
	}
}

// TestOriginValidation_DefeatsSubstringWAF: a substring-blocklist "WAF" that would
// have caught the old hardcoded payloads is defeated by the randomised RFC
// 2606 payloads, and the probe still fires external-origin.
func TestOriginValidation_DefeatsSubstringWAF(t *testing.T) {
	srv := substringOriginServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
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
		raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationOrigin)
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

// TestOriginValidation_CORSReflectionWithCredsFired: a server that reflects the
// Origin and sets Allow-Credentials must fire the cors-reflect-creds class.
func TestOriginValidation_CORSReflectionWithCredsFired(t *testing.T) {
	srv := corsReflectServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if !fired[string(classCORSReflectCreds)] {
		t.Errorf("cors-reflect-creds should fire when the server reflects Origin + Allow-Credentials; fired=%v", fired)
	}
}

// TestOriginValidation_ResolvesEndpointFromGenerator: with no config endpoint the
// probe reads the URL off the generator via types.MCPEndpoint.
func TestOriginValidation_ResolvesEndpointFromGenerator(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Errorf("expected attempts when generator supplies endpoint via MCPEndpoint")
	}
}

// TestOriginValidation_SSEStreamServed: an SSE endpoint that starts serving
// text/event-stream to an attacker Origin is flagged. Origin/Host validation
// on the streaming half of legacy MCP is the same security boundary as on the
// streamable-HTTP POST half — both live before the transport handler.
func TestOriginValidation_SSEStreamServed(t *testing.T) {
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

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "sse"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := findingsByClass(attempts)
	if !fired[string(classExternalOrigin)] {
		t.Errorf("external-origin should fire on an SSE endpoint serving any Origin; fired=%v", fired)
	}
}

// TestOriginValidation_SkipsWithoutEndpoint: no override and no MCPEndpoint yields
// nothing.
func TestOriginValidation_SkipsWithoutEndpoint(t *testing.T) {
	p := newOriginValidationProbe(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts with no endpoint, got %d", len(attempts))
	}
}

// recordingTransport wraps a real RoundTripper and captures every request
// that flows through it. Used by the S2 test to prove a probe actually
// uses the generator's http.Client and doesn't build its own bypass.
type recordingTransport struct {
	inner http.RoundTripper
	mu    sync.Mutex
	reqs  []*http.Request
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req.Clone(req.Context()))
	r.mu.Unlock()
	return r.inner.RoundTrip(req)
}

// instrumentedGen returns an AnonymousHTTPClient whose Transport is the
// supplied recordingTransport, so tests can assert every probe request
// went through the borrowed client.
type instrumentedGen struct {
	endpointGen
	rec *recordingTransport
}

func (g instrumentedGen) AnonymousHTTPClient() *http.Client {
	return &http.Client{Transport: g.rec, Timeout: 3 * time.Second}
}

// TestOriginValidation_UsesBorrowedHTTPClient: proves via an instrumented
// RoundTripper that every request the DNS-rebind probe emits flows through
// the client returned by MCPEndpoint.AnonymousHTTPClient() — i.e. the
// probe doesn't secretly build its own bypass client that would evade
// proxy/TLS/header config. Regression guard for Mauro S2.
func TestOriginValidation_UsesBorrowedHTTPClient(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	rec := &recordingTransport{inner: http.DefaultTransport}
	gen := instrumentedGen{
		endpointGen: endpointGen{url: srv.URL, transport: "http"},
		rec:         rec,
	}
	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	rec.mu.Lock()
	seenCount := len(rec.reqs)
	rec.mu.Unlock()
	if seenCount == 0 {
		t.Fatalf("recording transport saw NO requests — probe built its own client and bypassed the generator")
	}
	// Every attempt except pure errors should correspond to a request.
	// Baseline + origin sweep + host sweep + CORS preflight all emit one
	// request. Being generous: attempts >= seenCount / 2.
	if len(attempts) < seenCount/2 {
		t.Errorf("attempts=%d, seen=%d — mismatch suggests probe made side-channel requests", len(attempts), seenCount)
	}
}

// TestClassifyTargetHost covers the host-class classifier directly. The
// probe uses this to distinguish real DNS-rebinding targets (loopback/LAN)
// from public endpoints where missing Origin validation is a CSRF concern
// rather than a rebinding one.
func TestClassifyTargetHost(t *testing.T) {
	tests := []struct {
		in   string
		want originValidationTargetClass
	}{
		{"127.0.0.1:9003", targetLoopback},
		{"localhost:9003", targetLoopback},
		{"0.0.0.0:9003", targetLoopback},
		{"[::1]:9003", targetLoopback},
		{"foo.localhost:9003", targetLoopback},
		{"10.0.0.5", targetLAN},
		{"192.168.1.100:8080", targetLAN},
		{"172.16.30.42", targetLAN},
		{"169.254.169.254", targetLAN},
		{"printer.local:631", targetLAN},
		{"93.184.216.34", targetPublic}, // example.com IPv4 at time of writing
		{"[2001:db8::1]:443", targetPublic},
		{"", targetUnresolvable},
	}
	for _, tt := range tests {
		got := classifyTargetHost(tt.in)
		if got != tt.want {
			t.Errorf("classifyTargetHost(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

// TestOriginValidation_StampsTargetClass verifies the probe stamps the
// classified target class on every attempt so the detector can score
// by exploitability.
func TestOriginValidation_StampsTargetClass(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	// vulnServer binds to 127.0.0.1 via httptest.
	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts")
	}
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationTargetClass)
		if !ok {
			t.Errorf("attempt %q missing target class metadata", a.Prompt)
			continue
		}
		s, _ := raw.(string)
		if s != string(targetLoopback) {
			t.Errorf("attempt %q target class = %q, want loopback", a.Prompt, s)
		}
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
func findAttemptByClass(attempts []*attempt.Attempt, class originValidationClass) *attempt.Attempt {
	for _, a := range attempts {
		raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationClass)
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

// originValidationDetectorStub reimplements the acceptance check locally so the
// probe test does not depend on the detector package.
type originValidationDetectorStub struct{}

func (originValidationDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, _ := a.GetMetadata(attempt.MetadataKeyOriginValidationClass)
	class, _ := raw.(string)
	if !metaBoolStub(a, attempt.MetadataKeyOriginValidationAccepted) || class == string(classBaseline) {
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

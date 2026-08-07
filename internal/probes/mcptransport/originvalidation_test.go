package mcptransport

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

// findingsByClass runs the detector-side check and returns which attempt
// classes fired at least one 1.0 score. Since LAB-5584 the bypass sweep is a
// single attempt, so the only classes that can appear here are
// origin-validation-sweep and cors-reflect-creds — the per-variant classes
// live inside the sweep attempt's evidence (see acceptedVariantClasses).
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

// acceptedVariantClasses returns the per-variant classes the aggregated sweep
// attempt recorded as accepted.
func acceptedVariantClasses(t *testing.T, attempts []*attempt.Attempt) map[string]bool {
	t.Helper()
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated origin-validation-sweep attempt")
	}
	raw, ok := sweep.GetMetadata(attempt.MetadataKeyOriginValidationAcceptedClasses)
	if !ok {
		t.Fatal("sweep attempt is missing the accepted-classes metadata")
	}
	classes, _ := raw.([]string)
	got := map[string]bool{}
	for _, c := range classes {
		got[c] = true
	}
	return got
}

// sweepVariants returns the per-variant detail recorded on the aggregated
// sweep attempt.
func sweepVariants(t *testing.T, attempts []*attempt.Attempt) []map[string]any {
	t.Helper()
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated origin-validation-sweep attempt")
	}
	raw, ok := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariants)
	if !ok {
		t.Fatal("sweep attempt is missing the variants metadata")
	}
	vs, _ := raw.([]map[string]any)
	return vs
}

// TestOriginValidation_VulnerableServer: a server with no validation produces
// exactly ONE bypass finding, not one per variant — the LAB-5584 fix. Every
// variant class it accepted must still be recoverable from that one finding's
// evidence, because "which checks are missing" is what a remediator acts on.
func TestOriginValidation_VulnerableServer(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// Exactly one attempt scores as a bypass finding. Before LAB-5584 this
	// was nine.
	det := &originValidationDetectorStub{}
	findings := 0
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s == 1.0 {
				findings++
				break
			}
		}
	}
	if findings != 1 {
		t.Errorf("a server that validates nothing must produce 1 finding, got %d (attempts=%d)", findings, len(attempts))
	}

	fired := findingsByClass(attempts)
	if !fired[string(classSweep)] {
		t.Errorf("the aggregated sweep should fire on a fully-vulnerable server; fired=%v", fired)
	}
	if fired[string(classBaseline)] {
		t.Errorf("baseline should never fire as a finding")
	}

	// httptest binds 127.0.0.1:PORT, so swapCase is a no-op on the host and
	// the case-variant class is (correctly) skipped — see the
	// TestOriginValidation_CaseVariantSkippedOnNumericHost test below.
	acceptedClasses := acceptedVariantClasses(t, attempts)
	wantClasses := []string{
		string(classExternalOrigin),
		string(classNullOrigin),
		string(classExtensionOrigin),
		string(classLocalhostLookalike),
		string(classUnexpectedHost),
	}
	for _, c := range wantClasses {
		if !acceptedClasses[c] {
			t.Errorf("variant class %q should be listed as accepted in the sweep evidence (accepted=%v)", c, acceptedClasses)
		}
	}
	if acceptedClasses[string(classCaseVariant)] {
		t.Errorf("case-variant must NOT be accepted on an all-numeric host (would be an FP)")
	}
}

// TestOriginValidation_SweepEvidenceRecordsEveryVariant: the aggregated
// finding must account for every crafted value the probe sent, accepted or
// not. Collapsing ten findings into one is only safe if no evidence is lost.
func TestOriginValidation_SweepEvidenceRecordsEveryVariant(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated sweep attempt")
	}

	variants := sweepVariants(t, attempts)
	// Numeric host ⇒ case-variant skipped, so 7 Origin payloads + 2 Host.
	wantSent := len(p.buildOriginPayloads()) + len(p.buildHostPayloads())
	if len(variants) != wantSent {
		t.Errorf("sweep evidence lists %d variants, probe sent %d", len(variants), wantSent)
	}
	sent, _ := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariantsSent)
	if n, _ := sent.(int); n != wantSent {
		t.Errorf("variants_sent = %v, want %d", sent, wantSent)
	}
	acceptedCount, _ := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariantsAccepted)
	if n, _ := acceptedCount.(int); n != wantSent {
		t.Errorf("variants_accepted = %v, want %d (server validates nothing)", acceptedCount, wantSent)
	}

	// Every variant carries the header it sent and a response line, so the
	// evidence stands on its own without the old per-variant attempts.
	for i, v := range variants {
		if _, hasOrigin := v["origin"]; !hasOrigin {
			if _, hasHost := v["host"]; !hasHost {
				t.Errorf("variant %d records neither origin nor host: %v", i, v)
			}
		}
		if s, _ := v["result"].(string); s == "" {
			t.Errorf("variant %d has no result line: %v", i, v)
		}
	}
	if len(sweep.Outputs) != 1 {
		t.Errorf("aggregated attempt should carry exactly one evidence output, got %d", len(sweep.Outputs))
	}
	if !strings.Contains(sweep.Outputs[0], "NO Origin/Host validation is enforced") {
		t.Errorf("evidence should state the validator verdict for an any-origin server; got:\n%s", sweep.Outputs[0])
	}
}

// TestOriginValidation_PartialValidationStillOneFinding: a server that refuses
// some variants and accepts others is still ONE finding, and the evidence
// distinguishes which checks are missing.
func TestOriginValidation_PartialValidationStillOneFinding(t *testing.T) {
	// Refuses anything containing "example.com" but happily accepts
	// "example.net", "null", and extension origins — the shape of a
	// half-finished allowlist.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Origin"), "example.com") {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(initializeOK))
	}))
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	fired := findingsByClass(attempts)
	if !fired[string(classSweep)] {
		t.Fatalf("partial validation must still produce the aggregated finding; fired=%v", fired)
	}

	sweep := findAttemptByClass(attempts, classSweep)
	sent, _ := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariantsSent)
	got, _ := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariantsAccepted)
	sentN, _ := sent.(int)
	gotN, _ := got.(int)
	if gotN == 0 || gotN >= sentN {
		t.Errorf("expected a partial accept (0 < accepted < sent), got accepted=%d sent=%d", gotN, sentN)
	}
	if !strings.Contains(sweep.Outputs[0], "validation is PARTIAL") {
		t.Errorf("evidence should call out partial validation; got:\n%s", sweep.Outputs[0])
	}
	// The rejected variants must be visible too — that is what tells a
	// remediator the allowlist exists and is merely incomplete.
	if !strings.Contains(sweep.Outputs[0], "REJECTED") {
		t.Errorf("evidence should list the refused variants; got:\n%s", sweep.Outputs[0])
	}

	accepted := acceptedVariantClasses(t, attempts)
	if !accepted[string(classNullOrigin)] {
		t.Errorf("null-origin got through and should be listed as accepted; accepted=%v", accepted)
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
	for _, v := range sweepVariants(t, attempts) {
		if s, _ := v["class"].(string); s == string(classCaseVariant) {
			t.Errorf("case-variant should not be sent on a numeric host; got variant %v", v)
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
	if !fired[string(classSweep)] {
		t.Errorf("the sweep should fire against a substring-blocklist server; fired=%v", fired)
	}
	if accepted := acceptedVariantClasses(t, attempts); !accepted[string(classExternalOrigin)] {
		t.Errorf("external-origin should be among the accepted variants; accepted=%v", accepted)
	}

	// Confirm that none of the payloads we sent contained a blocklist token.
	origins := []string{}
	for _, v := range sweepVariants(t, attempts) {
		if o, ok := v["origin"].(string); ok {
			origins = append(origins, o)
		}
	}
	for _, a := range attempts {
		if raw, ok := a.GetMetadata(attempt.MetadataKeyOriginValidationOrigin); ok {
			o, _ := raw.(string)
			origins = append(origins, o)
		}
	}
	if len(origins) == 0 {
		t.Fatal("no Origin payloads recorded — the blocklist check would vacuously pass")
	}
	for _, o := range origins {
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

	// The reflection escalates the aggregated finding's stated impact: without
	// it a rebound page drives the tool surface blind; with it, it can read the
	// responses too.
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated sweep attempt")
	}
	if !metaBool(sweep, attempt.MetadataKeyOriginValidationCredentialedRead) {
		t.Errorf("sweep attempt should record the credentialed-read escalation")
	}
	if !strings.Contains(sweep.Outputs[0], "Credentialed CORS reflection: PRESENT") ||
		!strings.Contains(sweep.Outputs[0], "READ") {
		t.Errorf("aggregated evidence should escalate the impact when the preflight reflects credentials; got:\n%s", sweep.Outputs[0])
	}
}

// TestOriginValidation_NoCORSReflectionStatesLesserImpact: the escalation must
// be conditional — a server without credentialed reflection gets the lesser
// "blind" impact statement, so the escalated wording stays meaningful.
func TestOriginValidation_NoCORSReflectionStatesLesserImpact(t *testing.T) {
	srv := vulnServer(t)
	defer srv.Close()

	p := newOriginValidationProbe(t, registry.Config{"endpoint": srv.URL})
	attempts, err := p.Probe(context.Background(), endpointGen{url: srv.URL, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated sweep attempt")
	}
	if metaBool(sweep, attempt.MetadataKeyOriginValidationCredentialedRead) {
		t.Errorf("vulnServer sets no CORS headers; credentialed-read should be false")
	}
	if !strings.Contains(sweep.Outputs[0], "Credentialed CORS reflection: absent") {
		t.Errorf("evidence should state the lesser impact without reflection; got:\n%s", sweep.Outputs[0])
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
	if !fired[string(classSweep)] {
		t.Errorf("the sweep should fire on an SSE endpoint serving any Origin; fired=%v", fired)
	}
	if accepted := acceptedVariantClasses(t, attempts); !accepted[string(classExternalOrigin)] {
		t.Errorf("external-origin should be among the accepted variants on SSE; accepted=%v", accepted)
	}
}

// TestOriginValidation_AllVariantsFailedIsErrorNotSafe: when every request
// dies in transit the endpoint was never actually tested. Aggregation must not
// turn that into a green SAFE row — the whole point of one finding per
// endpoint is that the one row is trustworthy.
func TestOriginValidation_AllVariantsFailedIsErrorNotSafe(t *testing.T) {
	srv := vulnServer(t)
	url := srv.URL
	srv.Close() // nothing is listening now; every request fails to connect

	p := newOriginValidationProbe(t, registry.Config{"endpoint": url})
	attempts, err := p.Probe(context.Background(), endpointGen{url: url, transport: "http"})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated sweep attempt even when every variant failed")
	}
	if sweep.Status != attempt.StatusError {
		t.Errorf("sweep status = %q, want %q — a dead endpoint must not report as safe", sweep.Status, attempt.StatusError)
	}
	if sweep.Error == "" {
		t.Errorf("sweep should carry the transport error")
	}
	if _, ok := sweep.GetMetadata(attempt.MetadataKeyOriginValidationAccepted); ok {
		t.Errorf("sweep must not claim an accept/reject verdict when nothing was tested")
	}
	// The evidence still names every variant that could not be tested, so the
	// operator can see the sweep was not silently truncated.
	if !strings.Contains(sweep.Outputs[0], "NOT TESTED") {
		t.Errorf("evidence should list the untested variants; got:\n%s", sweep.Outputs[0])
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
	// Strict one-to-one against the requests the probe actually made. Since
	// LAB-5584 that is no longer len(attempts) — the sweep's variants share a
	// single attempt — so count them from the sweep's own record: baseline +
	// every variant + the preflight. Anything less proves the probe made a
	// side-channel request bypassing the borrowed client. Fixes CodeRabbit #8.
	sweep := findAttemptByClass(attempts, classSweep)
	if sweep == nil {
		t.Fatal("expected an aggregated sweep attempt")
	}
	raw, _ := sweep.GetMetadata(attempt.MetadataKeyOriginValidationVariantsSent)
	variantsSent, _ := raw.(int)
	wantRequests := 1 + variantsSent + 1 // baseline + sweep variants + preflight
	if seenCount != wantRequests {
		t.Errorf("requests=%d, seen=%d — not every request used the borrowed client (side-channel HTTP)", wantRequests, seenCount)
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
		got := classifyTargetHost(context.Background(), tt.in)
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

package toolsec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.DNSRebinding", NewDNSRebinding)
}

var _ types.ProbeMetadata = (*DNSRebinding)(nil)

// DNSRebinding probes an MCP HTTP endpoint for the server-side precondition of
// browser DNS-rebinding attacks: a target that accepts a request bearing an
// Origin (or Host) that a spec-compliant, allowlist-based validator would
// refuse.
//
// The probe is designed against how those validators are actually written:
//
//   - a strict-string allowlist (the shape shipped in patched MCP TypeScript
//     SDK 1.24 and the Java SDK 1.0 defence-in-depth PRs)
//   - a "$2 WAF" that substring-matches known-bad tokens like "attacker" or
//     "evil" (trivially bypassed and effectively no protection)
//   - a naive validator that uses contains/startsWith/case-insensitive match
//     over "localhost" or the expected hostname
//   - a CORS layer that reflects the request Origin plus credentials — the
//     mechanism that lets a browser attacker read the response, not just send
//     the request
//
// Payloads are randomised per run using RFC 2606-reserved test domains, so no
// value the probe sends is a static regex match for a signature-based WAF —
// yet every value is a domain a real attacker could plausibly control.
type DNSRebinding struct {
	endpointOverride   string
	insecureSkipVerify bool
	timeout            time.Duration
	// nonce is used to build randomised Origin/Host values so the probe never
	// sends the same wire-string twice across runs, defeating cheap blocklist
	// WAFs and letting re-scans confirm intermittent behaviour.
	nonce string
}

// NewDNSRebinding constructs the probe. The endpoint is resolved from the
// target generator when it implements types.MCPEndpoint; the "endpoint" config
// key overrides that when set.
func NewDNSRebinding(cfg registry.Config) (probes.Prober, error) {
	return &DNSRebinding{
		endpointOverride:   registry.GetString(cfg, "endpoint", ""),
		insecureSkipVerify: registry.GetBool(cfg, "insecure_skip_verify", false),
		timeout:            time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
		nonce:              randToken(),
	}, nil
}

func (p *DNSRebinding) Name() string { return "toolsec.DNSRebinding" }

func (p *DNSRebinding) Description() string {
	return "Sends MCP initialize (and CORS preflight) with randomised Origin/Host values that a spec-compliant validator must refuse; classifies which validator weakness (any-origin, null, extension, localhost-lookalike, case-variant, credentialed CORS reflection) the target exhibits"
}

func (p *DNSRebinding) Goal() string {
	return "Determine whether the MCP HTTP endpoint's Origin/Host validation is strong enough to block browser DNS-rebinding — and if not, which specific class of bypass succeeds"
}

func (p *DNSRebinding) GetPrimaryDetector() string { return "toolsec.DNSRebinding" }

func (p *DNSRebinding) GetPrompts() []string {
	return []string{"Randomised MCP initialize + CORS preflight bearing Origin/Host values a rebinding-protected server should refuse"}
}

// dnsRebindClass is a stable classifier for a bypass, so a report can group
// findings by concrete validator weakness rather than one lumped verdict.
type dnsRebindClass string

const (
	classBaseline           dnsRebindClass = "baseline"
	classExternalOrigin     dnsRebindClass = "external-origin"
	classNullOrigin         dnsRebindClass = "null-origin"
	classExtensionOrigin    dnsRebindClass = "extension-origin"
	classLocalhostLookalike dnsRebindClass = "localhost-lookalike"
	classCaseVariant        dnsRebindClass = "case-variant"
	classUnexpectedHost     dnsRebindClass = "unexpected-host"
	classCORSReflectCreds   dnsRebindClass = "cors-reflect-creds"
)

// mcpInitializePayload is the smallest MCP initialize the server must be
// willing to answer to demonstrate that it accepted our request. The exact
// protocol version matters less than whether the server processes the
// JSON-RPC at all; a server that would refuse this on Origin grounds returns
// 403 or a CORS-style rejection, not a well-formed initialize result.
const mcpInitializePayload = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"augustus-scan","version":"1.0"}}}`

// buildOriginPayloads renders every Origin bypass class as a concrete header
// value against a fresh per-run nonce. RFC 2606 reserved test domains
// (example.com/.net/.org) ensure the values are non-routable *and* look like
// benign analytics / CDN traffic to any string-blocklist WAF.
func (p *DNSRebinding) buildOriginPayloads() []originPayload {
	tag := p.nonce[:8]
	return []originPayload{
		// External origin — the primary finding. A random subdomain of an
		// RFC 2606 domain so no static blocklist ("evil", "attacker", ...)
		// hits, yet every request is unambiguously cross-origin.
		{class: classExternalOrigin, value: "https://" + tag + ".example.com"},
		{class: classExternalOrigin, value: "https://cdn-" + tag + ".example.net"},
		// null: what browsers send from sandbox iframes and file:// contexts.
		// Some naive validators explicitly allow "null" for tests and never
		// remove it; a rebinding-capable page can force this via iframe.
		{class: classNullOrigin, value: "null"},
		// Extension origin — a real malicious-extension shape. Attackers who
		// ship a rogue extension get to pick the Origin, and it looks like
		// this. UUID-shaped to blend with legitimate extension traffic.
		{class: classExtensionOrigin, value: "chrome-extension://" + extensionID(tag)},
		{class: classExtensionOrigin, value: "moz-extension://" + extensionUUID(tag)},
		// Localhost-lookalike — catches validators that use
		// contains("localhost") / startsWith("localhost") / suffix match.
		// A real attacker can register any of these because they are only
		// meaningful *relative* to the string check.
		{class: classLocalhostLookalike, value: "http://localhost." + tag + ".example.com"},
		{class: classLocalhostLookalike, value: "http://127.0.0.1." + tag + ".example.net"},
	}
}

// buildHostPayloads renders unexpected Host header values. These test whether
// the server enforces a Host allowlist independent of Origin (some SDKs do
// both, some only one). Values are RFC 2606-reserved and randomised.
func (p *DNSRebinding) buildHostPayloads() []hostPayload {
	tag := p.nonce[:8]
	return []hostPayload{
		{class: classUnexpectedHost, value: tag + ".example.com"},
		// Sub-127.0.0.1 label — same trick as localhost-lookalike but at the
		// Host layer.
		{class: classUnexpectedHost, value: "127.0.0.1." + tag + ".example.net"},
	}
}

type originPayload struct {
	class dnsRebindClass
	value string
}

type hostPayload struct {
	class dnsRebindClass
	value string
}

// extensionID returns a Chrome-extension-id-shaped string (32 lowercase
// letters). The exact byte pattern doesn't matter to the target; the shape
// does, so a shape-matching validator ("looks like an extension id → allow")
// exposes itself.
func extensionID(seed string) string {
	// Deterministic-per-seed but uses the seed's bytes to fill 32 letters.
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		c := seed[i%len(seed)]
		if c >= '0' && c <= '9' {
			c = 'a' + (c - '0')
		}
		if c < 'a' || c > 'p' {
			c = 'a' + (c%16)
		}
		out[i] = c
	}
	return string(out)
}

// extensionUUID renders the seed as an 8-4-4-4-12 UUID-shaped hex string.
func extensionUUID(seed string) string {
	// Pad or truncate seed to 32 hex-shaped chars, then insert dashes.
	src := (seed + "0123456789abcdef0123456789abcdef")[:32]
	return src[:8] + "-" + src[8:12] + "-" + src[12:16] + "-" + src[16:20] + "-" + src[20:32]
}

// Probe resolves the endpoint and runs the full sweep. Returns no attempts (no
// error) for non-HTTP transports or absent endpoints.
func (p *DNSRebinding) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("toolsec.DNSRebinding: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("toolsec.DNSRebinding: skipping non-HTTP transport", "endpoint", endpoint)
		return nil, nil
	}
	// Pick the request shape from the transport. The security question is the
	// same for both — does the server serve this request when the Origin is
	// attacker-controlled? — but the HTTP fingerprint differs:
	//
	//   streamable HTTP  POST endpoint  with JSON-RPC initialize; acceptance
	//                    is a JSON-RPC (or SSE) 200 response.
	//   legacy SSE       GET /sse; acceptance is 200 with a text/event-stream
	//                    response (the server started serving the stream
	//                    before we could get a session).
	//
	// A browser DNS-rebinding attacker gets exactly one HTTP round trip after
	// the rebind; whether they use GET /sse or POST /message doesn't matter
	// to the Origin check that runs BEFORE either handler.
	transport := "http"
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok && mcpEnd.Transport() == "sse" {
		transport = "sse"
	}

	client := p.newHTTPClient()
	var attempts []*attempt.Attempt

	// 1. Baseline: no Origin. Spec-compliant servers pass this; if it fails,
	// we can't distinguish "server rejected our headers" from "server can't
	// accept us at all," so the whole sweep is inconclusive. We record the
	// attempt either way.
	base := p.probeAccess(ctx, client, endpoint, transport, "", "", classBaseline)
	attempts = append(attempts, base)
	if !metaBool(base, attempt.MetadataKeyDNSRebindAccepted) {
		slog.Info("toolsec.DNSRebinding: baseline (no Origin) not accepted; downstream bypass results may be inconclusive", "endpoint", endpoint, "transport", transport)
	}

	// 2. Origin bypass sweep.
	for _, o := range p.buildOriginPayloads() {
		attempts = append(attempts, p.probeAccess(ctx, client, endpoint, transport, o.value, "", o.class))
	}

	// 3. Case-variant of the expected host — tests case-sensitive vs
	// insensitive matching against whatever hostname the server considers
	// canonical. Case-shifted request Origin matches the target's host with
	// scheme forced to http.
	if u.Host != "" {
		caseHost := "http://" + swapCase(u.Host)
		attempts = append(attempts, p.probeAccess(ctx, client, endpoint, transport, caseHost, "", classCaseVariant))
	}

	// 4. Host header sweep.
	for _, h := range p.buildHostPayloads() {
		attempts = append(attempts, p.probeAccess(ctx, client, endpoint, transport, "", h.value, h.class))
	}

	// 5. CORS preflight — OPTIONS with an external Origin, inspect
	// Access-Control-Allow-Origin echo + Allow-Credentials. A server that
	// reflects the attacker Origin with credentials is exploitable regardless
	// of whether the POST body succeeds, because a browser DNS-rebinding
	// attacker can read the response.
	attempts = append(attempts, p.probePreflight(ctx, client, endpoint, "https://"+p.nonce[:8]+".example.org", u.Host))

	return attempts, nil
}

// resolveEndpoint returns the endpoint URL from probe config (explicit
// override wins) or from the generator via types.MCPEndpoint.
func (p *DNSRebinding) resolveEndpoint(gen types.Generator) string {
	if p.endpointOverride != "" {
		return p.endpointOverride
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// probeAccess sends the transport-appropriate request (POST initialize for
// streamable HTTP; GET /sse for legacy SSE) bearing the crafted Origin/Host
// headers, classifies the response, and returns the attempt. Empty origin /
// host means "leave unset" (baseline shape). The security question — did the
// server serve this request from an untrusted caller — is answered by the
// SAME defensive middleware regardless of what payload follows: Origin/Host
// validation runs before either handler.
func (p *DNSRebinding) probeAccess(ctx context.Context, client *http.Client, endpoint, transport, origin, host string, class dnsRebindClass) *attempt.Attempt {
	label := describeAttempt(origin, host, class)
	a := attempt.New(label)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyDNSRebindClass] = string(class)
	if origin != "" {
		a.Metadata[attempt.MetadataKeyDNSRebindOrigin] = origin
	}
	if host != "" {
		a.Metadata[attempt.MetadataKeyDNSRebindHost] = host
	}

	var (
		req    *http.Request
		method string
		err    error
	)
	if transport == "sse" {
		// GET /sse — the browser-reachable half of legacy MCP. We use a very
		// short context deadline (see newHTTPClient's sseCtx) so we don't
		// hang on the stream; we only need to know whether the server BEGAN
		// serving it.
		sseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		req, err = http.NewRequestWithContext(sseCtx, http.MethodGet, endpoint, nil)
		req.Header.Set("Accept", "text/event-stream")
		method = "GET"
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(mcpInitializePayload))
		if req != nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
		}
		method = "POST"
	}
	if err != nil {
		a.SetError(err)
		return a
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if host != "" {
		// net/http honours req.Host on the wire; Header["Host"] is silently
		// dropped. Set both for defensive symmetry with unusual middlewares
		// that inspect the header map.
		req.Host = host
		req.Header.Set("Host", host)
	}

	resp, err := client.Do(req)
	if err != nil {
		// For SSE we intentionally cancel the read soon after headers, so a
		// context-deadline error AFTER the response headers arrived is not a
		// probe failure — record what we have and let the classifier decide.
		if transport == "sse" && resp != nil {
			// Fall through to classify below.
		} else {
			a.SetError(fmt.Errorf("%s %s: %w", method, endpoint, err))
			return a
		}
	}
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()

	var (
		status      int
		contentType string
		body        []byte
	)
	if resp != nil {
		status = resp.StatusCode
		contentType = resp.Header.Get("Content-Type")
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	}
	a.AddOutput(fmt.Sprintf("%s %s -> HTTP %d\nContent-Type: %s\n%s", method, endpoint, status, contentType, string(body)))
	a.Complete()

	var accepted bool
	if transport == "sse" {
		accepted = serverStartedSSEStream(status, contentType)
	} else {
		accepted = serverProcessedInitialize(status, contentType, body)
	}
	a.Metadata[attempt.MetadataKeyDNSRebindAccepted] = accepted
	return a
}

// serverStartedSSEStream reports whether the server responded 2xx with a
// text/event-stream body — the signal that it *served* the request rather
// than rejecting it on Origin/Host grounds. We read only the response
// headers; any body bytes are drained but not required. A rejection surfaces
// as 4xx (403/406) or a non-event-stream content type.
func serverStartedSSEStream(status int, contentType string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	return strings.Contains(strings.ToLower(contentType), "text/event-stream")
}

// probePreflight sends an OPTIONS preflight with an external Origin and
// classifies the CORS response. If the server reflects the Origin *and* sets
// Allow-Credentials: true, a browser DNS-rebinding attacker can read the
// response — a more severe finding than a simple accepted-Origin because
// unauthenticated reads become possible.
func (p *DNSRebinding) probePreflight(ctx context.Context, client *http.Client, endpoint, origin, expectedHost string) *attempt.Attempt {
	a := attempt.New("CORS preflight from " + origin)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyDNSRebindClass] = string(classCORSReflectCreds)
	a.Metadata[attempt.MetadataKeyDNSRebindOrigin] = origin

	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpoint, nil)
	if err != nil {
		a.SetError(err)
		return a
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")

	resp, err := client.Do(req)
	if err != nil {
		a.SetError(err)
		return a
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8*1024))

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	a.Metadata[attempt.MetadataKeyDNSRebindAllowOrigin] = allowOrigin
	a.Metadata[attempt.MetadataKeyDNSRebindAllowCreds] = allowCreds
	a.AddOutput(fmt.Sprintf("HTTP %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %v", resp.StatusCode, allowOrigin, allowCreds))
	a.Complete()

	// A "*" ACAO with credentials is *ignored* by browsers, so it isn't a
	// real credentialed-read primitive — we only flag reflection of the
	// exact Origin we sent, combined with credentials.
	reflected := allowOrigin == origin && allowCreds
	a.Metadata[attempt.MetadataKeyDNSRebindAccepted] = reflected
	return a
}

// serverProcessedInitialize reports whether the response looks like the
// server actually handled the JSON-RPC (as opposed to rejecting it at the
// HTTP layer). 2xx with a JSON-RPC-shaped body, or an SSE stream.
func serverProcessedInitialize(status int, contentType string, body []byte) bool {
	if status < 200 || status >= 300 {
		return false
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/event-stream") {
		return true
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return false
	}
	return envelope.JSONRPC == "2.0" && (len(envelope.Result) > 0 || len(envelope.Error) > 0)
}

// describeAttempt renders a short label for the attempt list.
func describeAttempt(origin, host string, class dnsRebindClass) string {
	switch {
	case origin != "" && host != "":
		return fmt.Sprintf("[%s] Origin=%s Host=%s", class, origin, host)
	case origin != "":
		return fmt.Sprintf("[%s] Origin=%s", class, origin)
	case host != "":
		return fmt.Sprintf("[%s] Host=%s", class, host)
	default:
		return fmt.Sprintf("[%s] no Origin/Host (baseline)", class)
	}
}

// swapCase flips ASCII case so a validator that lowercases neither side
// mistakenly rejects the request; a case-insensitive validator returns the
// same verdict as for the canonical host, which is the point of the probe.
func swapCase(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = c - 32
		case c >= 'A' && c <= 'Z':
			out[i] = c + 32
		default:
			out[i] = c
		}
	}
	return string(out)
}

// metaBool reads a boolean attempt-metadata value tolerating JSON round-trip.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

// newHTTPClient builds the client used for the probe. It does NOT follow
// redirects (a 302 to a different host confuses the Origin/Host signal) and
// honours insecure_skip_verify for lab targets.
func (p *DNSRebinding) newHTTPClient() *http.Client {
	tr := &http.Transport{
		// #nosec G402 -- insecure_skip_verify is opt-in for lab targets, matching the MCP generator.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.insecureSkipVerify},
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

package mcptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// originValidationTargetClass tags an endpoint host by DNS-rebinding relevance.
// See MetadataKeyOriginValidationTargetClass for what each value means.
type originValidationTargetClass string

const (
	targetLoopback     originValidationTargetClass = "loopback"
	targetLAN          originValidationTargetClass = "lan"
	targetPublic       originValidationTargetClass = "public"
	targetUnresolvable originValidationTargetClass = "unresolvable"
)

// classifyTargetHost inspects the endpoint host and buckets it by DNS-
// rebinding relevance. Order of decision:
//
//  1. Literal "localhost" or "0.0.0.0" → loopback (even before resolution).
//  2. Parse as IP. If success, classify by IP class (loopback / RFC1918 /
//     link-local / else public).
//  3. Otherwise DNS-resolve. If ANY resolved IP is loopback, treat as
//     loopback (worst case wins for exploitability). Else if any is LAN,
//     LAN. Else public.
//  4. Resolution failure → unresolvable.
//
// This is the single-shot exploitability heuristic; the detector uses
// the returned class to decide whether a missing-Origin finding scores
// as full VULN (loopback/lan, real DNS rebinding) or inconclusive
// (public/unresolvable, CSRF-class or unknown deployment context).
func classifyTargetHost(host string) originValidationTargetClass {
	if host == "" {
		return targetUnresolvable
	}
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Strip brackets from IPv6 literals.
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "0.0.0.0" || strings.HasSuffix(lower, ".localhost") {
		return targetLoopback
	}
	// mDNS .local — assume LAN (usually rebindable when browsers share the
	// same LAN).
	if strings.HasSuffix(lower, ".local") {
		return targetLAN
	}
	// If host parses as an IP directly, classify from it.
	if ip := net.ParseIP(host); ip != nil {
		return classifyIP(ip)
	}
	// Hostname → DNS lookup. Worst class wins.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return targetUnresolvable
	}
	worst := targetPublic
	for _, ip := range ips {
		c := classifyIP(ip)
		if rank(c) < rank(worst) {
			worst = c
		}
	}
	return worst
}

// classifyIP buckets a single IP.
func classifyIP(ip net.IP) originValidationTargetClass {
	if ip.IsLoopback() || ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6unspecified) {
		return targetLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return targetLAN
	}
	if ip.IsPrivate() {
		return targetLAN
	}
	return targetPublic
}

// rank orders classes worst-first for the "worst-of-many" resolution rule.
// Lower rank = higher exploitability concern.
func rank(c originValidationTargetClass) int {
	switch c {
	case targetLoopback:
		return 0
	case targetLAN:
		return 1
	case targetPublic:
		return 2
	default:
		return 3
	}
}

func init() {
	probes.Register("mcptransport.OriginValidation", NewOriginValidation)
}

var _ types.ProbeMetadata = (*OriginValidation)(nil)

// OriginValidation probes an MCP HTTP endpoint for the server-side precondition of
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
type OriginValidation struct {
	endpointOverride string
	timeout          time.Duration
	// nonce is used to build randomised Origin/Host values so the probe never
	// sends the same wire-string twice across runs, defeating cheap blocklist
	// WAFs and letting re-scans confirm intermittent behaviour.
	nonce string
}

// NewOriginValidation constructs the probe. The endpoint is resolved from the
// target generator when it implements types.MCPEndpoint; the "endpoint" config
// key overrides that when set. Proxy, TLS, and per-request headers are
// inherited from the target generator's HTTPClient — configure them there,
// not on this probe.
func NewOriginValidation(cfg registry.Config) (probes.Prober, error) {
	return &OriginValidation{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
		nonce:            randToken(),
	}, nil
}

func (p *OriginValidation) Name() string { return "mcptransport.OriginValidation" }

func (p *OriginValidation) Description() string {
	return "Tests MCP HTTP endpoints for missing Origin/Host validation — the mitigation MCP servers must implement to block browser DNS-rebinding attacks (CVE-2025-49596 class). Classifies the target host at probe time: loopback / RFC1918-LAN targets get full-VULN scoring because they are the browser-driven-rebinding attack path; public endpoints get inconclusive scoring because the same wire finding is CSRF-class rather than rebinding-class there, and exploitability depends on cookie/auth deployment context the probe cannot inspect."
}

func (p *OriginValidation) Goal() string {
	return "Determine whether the MCP HTTP endpoint enforces the Origin/Host validation the MCP spec requires. Score = 1.0 on loopback/LAN targets (real DNS-rebinding precondition), InconclusiveScore on public/unresolvable targets (spec violation with different attack-class implications)."
}

func (p *OriginValidation) GetPrimaryDetector() string { return "mcptransport.OriginValidation" }

func (p *OriginValidation) GetPrompts() []string {
	return []string{"Randomised MCP initialize + CORS preflight bearing Origin/Host values a rebinding-protected server should refuse"}
}

// originValidationClass is a stable classifier for a bypass, so a report can group
// findings by concrete validator weakness rather than one lumped verdict.
type originValidationClass string

const (
	classBaseline           originValidationClass = "baseline"
	classExternalOrigin     originValidationClass = "external-origin"
	classNullOrigin         originValidationClass = "null-origin"
	classExtensionOrigin    originValidationClass = "extension-origin"
	classLocalhostLookalike originValidationClass = "localhost-lookalike"
	classCaseVariant        originValidationClass = "case-variant"
	classUnexpectedHost     originValidationClass = "unexpected-host"
	classCORSReflectCreds   originValidationClass = "cors-reflect-creds"
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
func (p *OriginValidation) buildOriginPayloads() []originPayload {
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
func (p *OriginValidation) buildHostPayloads() []hostPayload {
	tag := p.nonce[:8]
	return []hostPayload{
		{class: classUnexpectedHost, value: tag + ".example.com"},
		// Sub-127.0.0.1 label — same trick as localhost-lookalike but at the
		// Host layer.
		{class: classUnexpectedHost, value: "127.0.0.1." + tag + ".example.net"},
	}
}

type originPayload struct {
	class originValidationClass
	value string
}

type hostPayload struct {
	class originValidationClass
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
			c = 'a' + (c % 16)
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
func (p *OriginValidation) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.OriginValidation: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("mcptransport.OriginValidation: skipping non-HTTP transport", "endpoint", endpoint)
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

	// Classify the target's host BEFORE sending anything. The class flows
	// into every attempt's metadata; the detector uses it to distinguish
	// real DNS-rebinding preconditions (loopback/LAN) from spec-violation-
	// only findings on public endpoints (CSRF-class, not rebinding, needs
	// deployment context to assess).
	targetClass := classifyTargetHost(u.Host)
	slog.Info("mcptransport.OriginValidation: target host classified",
		"host", u.Host, "class", string(targetClass))

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}
	var attempts []*attempt.Attempt

	// Helper: every attempt inherits the target class so the detector can
	// score by exploitability.
	stampClass := func(a *attempt.Attempt) *attempt.Attempt {
		a.Metadata[attempt.MetadataKeyOriginValidationTargetClass] = string(targetClass)
		return a
	}

	// 1. Baseline: no Origin. Spec-compliant servers pass this; if it fails,
	// we can't distinguish "server rejected our headers" from "server can't
	// accept us at all," so the whole sweep is inconclusive. We record the
	// attempt either way.
	base := stampClass(p.probeAccess(ctx, client, endpoint, transport, "", "", classBaseline))
	attempts = append(attempts, base)
	if !metaBool(base, attempt.MetadataKeyOriginValidationAccepted) {
		slog.Info("mcptransport.OriginValidation: baseline (no Origin) not accepted; downstream bypass results may be inconclusive", "endpoint", endpoint, "transport", transport)
	}

	// 2. Origin bypass sweep.
	for _, o := range p.buildOriginPayloads() {
		attempts = append(attempts, stampClass(p.probeAccess(ctx, client, endpoint, transport, o.value, "", o.class)))
	}

	// 3. Case-variant of the expected host — tests case-sensitive vs
	// insensitive matching against whatever hostname the server considers
	// canonical. Case-shifted request Origin matches the target's host with
	// scheme forced to http.
	//
	// Skip when the host is all-numeric (e.g. "127.0.0.1:9003") — swapCase
	// is a no-op there, so we'd send the server's OWN canonical Origin and
	// a correctly-hardened allowlist server would accept it, giving a false
	// positive on the case-variant class.
	if u.Host != "" {
		caseHost := swapCase(u.Host)
		if caseHost != u.Host {
			attempts = append(attempts, stampClass(p.probeAccess(ctx, client, endpoint, transport, "http://"+caseHost, "", classCaseVariant)))
		}
	}

	// 4. Host header sweep.
	for _, h := range p.buildHostPayloads() {
		attempts = append(attempts, stampClass(p.probeAccess(ctx, client, endpoint, transport, "", h.value, h.class)))
	}

	// 5. CORS preflight — OPTIONS with an external Origin, inspect
	// Access-Control-Allow-Origin echo + Allow-Credentials. A server that
	// reflects the attacker Origin with credentials is exploitable regardless
	// of whether the POST body succeeds, because a browser DNS-rebinding
	// attacker can read the response.
	attempts = append(attempts, stampClass(p.probePreflight(ctx, client, endpoint, "https://"+p.nonce[:8]+".example.org", u.Host)))

	return attempts, nil
}

// resolveEndpoint returns the endpoint URL from probe config (explicit
// override wins) or from the generator via types.MCPEndpoint.
func (p *OriginValidation) resolveEndpoint(gen types.Generator) string {
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
func (p *OriginValidation) probeAccess(ctx context.Context, client *http.Client, endpoint, transport, origin, host string, class originValidationClass) *attempt.Attempt {
	label := describeAttempt(origin, host, class)
	a := attempt.New(label)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = string(class)
	if origin != "" {
		a.Metadata[attempt.MetadataKeyOriginValidationOrigin] = origin
	}
	if host != "" {
		a.Metadata[attempt.MetadataKeyOriginValidationHost] = host
	}

	var (
		req    *http.Request
		method string
		err    error
	)
	if transport == "sse" {
		// GET /sse — the browser-reachable half of legacy MCP. We use a very
		// short context deadline so we don't hang on the stream; we only
		// need to know whether the server BEGAN serving it (status +
		// content-type; body is drained without reading — see below).
		sseCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		req, err = http.NewRequestWithContext(sseCtx, http.MethodGet, endpoint, nil)
		method = "GET"
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(mcpInitializePayload))
		method = "POST"
	}
	if err != nil {
		a.SetError(err)
		return a
	}
	// Set method-specific headers AFTER the nil check so both branches share
	// the same guard (previously the SSE branch touched req before the check,
	// a latent panic if NewRequestWithContext ever returned err+nil-req).
	if transport == "sse" {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
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
		// For SSE we deliberately DON'T read the body: the stream stays
		// open indefinitely and io.ReadAll would block until the 2-second
		// context deadline for every payload (~26s total across the sweep).
		// serverStartedSSEStream inspects only status + content-type, so
		// the body doesn't add information — just latency.
		if transport != "sse" {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		}
	}
	a.AddOutput(fmt.Sprintf("%s %s -> HTTP %d\nContent-Type: %s\n%s", method, endpoint, status, contentType, string(body)))
	a.Complete()

	var accepted bool
	if transport == "sse" {
		accepted = serverStartedSSEStream(status, contentType)
	} else {
		accepted = serverProcessedInitialize(status, contentType, body)
	}
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = accepted
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
func (p *OriginValidation) probePreflight(ctx context.Context, client *http.Client, endpoint, origin, expectedHost string) *attempt.Attempt {
	a := attempt.New("CORS preflight from " + origin)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = string(classCORSReflectCreds)
	a.Metadata[attempt.MetadataKeyOriginValidationOrigin] = origin

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
	a.Metadata[attempt.MetadataKeyOriginValidationAllowOrigin] = allowOrigin
	a.Metadata[attempt.MetadataKeyOriginValidationAllowCreds] = allowCreds
	a.AddOutput(fmt.Sprintf("HTTP %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %v", resp.StatusCode, allowOrigin, allowCreds))
	a.Complete()

	// A "*" ACAO with credentials is *ignored* by browsers, so it isn't a
	// real credentialed-read primitive — we only flag reflection of the
	// exact Origin we sent, combined with credentials.
	reflected := allowOrigin == origin && allowCreds
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = reflected
	return a
}

// serverProcessedInitialize reports whether the response looks like the
// server actually ACCEPTED our request (as opposed to rejecting it, either
// at the HTTP layer or inside the JSON-RPC envelope). Accepted means:
//   - 2xx + text/event-stream (streamable-HTTP servers may respond with SSE
//     to initialize; the stream itself is proof of acceptance), OR
//   - 2xx + a JSON-RPC 2.0 envelope with a non-empty `result` field.
//
// A 2xx bearing a JSON-RPC `error` envelope is NOT counted as accepted:
// a well-behaved server may catch an Origin/Host violation at the app
// layer and surface it inside the RPC envelope (returning 200 + error)
// rather than as an HTTP 403. Treating that as "processed" would flag a
// hardened server as vulnerable. When only an error is present, the
// server engaged with the request but explicitly refused it — no bypass
// to report.
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
	return envelope.JSONRPC == "2.0" && len(envelope.Result) > 0
}

// describeAttempt renders a short label for the attempt list.
func describeAttempt(origin, host string, class originValidationClass) string {
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

// metaBool lives in mcptransport.go (shared with the sibling
// SSESessionHijack probe).

// borrowHTTPClient returns the generator's anonymous http.Client (proxy +
// TLS inherited, but NO auth/scan-tag headers), layered with this probe's
// per-run overrides (short timeout, no redirect-follow).
//
// DNS-rebinding models a browser-driven attacker who does not hold the
// operator's bearer token; sending the token would make a correctly-
// hardened AUTHENTICATED server accept the request (because we're
// authenticated) and score it as vulnerable — inverting the verdict.
// AnonymousHTTPClient strips the headerTransport so we're indistinguishable
// on the wire from an attacker page.
//
// If the target generator does not expose types.MCPEndpoint (probe was
// pointed at an endpoint URL directly via config, no live generator), we
// fall back to a plain client — the operator has explicitly opted out of
// the generator layer and no proxy inheritance is possible.
func (p *OriginValidation) borrowHTTPClient(gen types.Generator) (*http.Client, error) {
	timeout := p.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	noRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if end, ok := gen.(types.MCPEndpoint); ok {
		client := end.AnonymousHTTPClient()
		client.Timeout = timeout
		client.CheckRedirect = noRedirect
		return client, nil
	}
	return &http.Client{Timeout: timeout, CheckRedirect: noRedirect}, nil
}

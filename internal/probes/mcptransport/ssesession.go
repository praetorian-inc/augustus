package mcptransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptransport.SSESessionHijack", NewSSESessionHijack)
}

var _ types.ProbeMetadata = (*SSESessionHijack)(nil)

// SSESessionHijack tests the legacy MCP SSE transport for session-management
// weakness that would let an attacker who obtains a session ID (via any
// out-of-band leak — logs, referer, browser history, network interception,
// DNS rebinding) drive the session.
//
// Attack family: session hijacking / broken session binding (CWE-287, CWE-
// 613, MCP07). The transport is SSE only because that's where MCP puts
// session IDs today; the underlying weakness is transport-agnostic.
//
// LLM-security scope: the probe answers the question "if an attacker
// obtains a session ID by any means, can they use it to drive the MCP
// session and invoke tools?" A yes gives the attacker LLM-level
// primitive access via the MCP tool surface. A no doesn't.
//
// The probe obtains ONE valid session ID via a normal SSE handshake
// and runs three replay tests:
//
//  1. Unknown-ID control — POST with a fabricated session id. Server
//     must reject; if it accepts, the target has no session validation
//     at all and downstream replay findings are suppressed as FPs.
//
//  2. session-not-tcp-bound — POST from a fresh TCP conn WITH the SSE
//     stream still open. If the server accepts, the session ID is a
//     naked bearer token — an attacker who obtains it can drive the
//     session from anywhere (CWE-287).
//
//  3. session-post-close-alive — close the SSE stream, wait 500 ms,
//     then POST. If accepted, the session outlives its stream (CWE-613).
//
// What the probe DOES NOT do: session-ID entropy / shape audit.
// Those checks were classic web-app hygiene (CWE-330) rather than
// LLM-specific security. General web-app scanners cover them better,
// and augustus's mission is LLM vulnerability testing. Retired
// classes: session-id-short, session-id-low-diversity,
// session-id-guessable-shape. See PR #234 discussion for the scope
// call.
type SSESessionHijack struct {
	endpointOverride string
	timeout          time.Duration
}

// NewSSESessionHijack constructs the probe. Proxy, TLS, and per-request
// headers are inherited from the target generator's HTTPClient — configure
// them on the generator, not on this probe.
func NewSSESessionHijack(cfg registry.Config) (probes.Prober, error) {
	return &SSESessionHijack{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
	}, nil
}

func (p *SSESessionHijack) Name() string { return "mcptransport.SSESessionHijack" }

var _ types.RiskDescriber = (*SSESessionHijack)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *SSESessionHijack) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP server accepts its SSE session identifier as a bearer token that is not bound to the connection or lifetime it was issued for — the ID is honored when replayed on a separate connection or after its stream has closed. Sampled identifiers also showed limited entropy or shared prefixes.",
		Impact:         "Someone who obtains a session ID — from logs, a Referer header, a proxy, or (given weak entropy) guessing — can reuse it to act with the victim's authority over the MCP tool surface.",
		Recommendation: "Bind each session to its connection and an authenticated principal, and require a secret credential on every request rather than the session ID alone. Generate IDs from a secure RNG, expire them when the stream closes and after an idle timeout, and reject any ID replayed on a different connection.",
		References:     "https://cwe.mitre.org/data/definitions/287.html\nhttps://cwe.mitre.org/data/definitions/330.html\nhttps://cwe.mitre.org/data/definitions/613.html\nhttps://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
		Taxonomies:     "- cwe: 287\n- cwe: 330\n- cwe: 613",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
	}
}

func (p *SSESessionHijack) Description() string {
	return "Tests MCP SSE session-management for hijack primitives: obtains one valid session ID via a normal SSE handshake, then replays it off the original TCP connection (with stream still open — the true cross-connection replay test) and again after the stream closes. If either replay is accepted, the ID is a naked bearer token that any attacker who obtains it can use to drive the MCP tool surface."
}

func (p *SSESessionHijack) Goal() string {
	return "Determine whether a session ID obtained via any means (leak, log, referer, DNS rebind) is a naked bearer token — reusable off the TCP connection that created it, or surviving past its stream. LLM-relevant because a hijacked MCP session gives arbitrary tool-invocation."
}

func (p *SSESessionHijack) GetPrimaryDetector() string { return "mcptransport.SSESessionHijack" }

func (p *SSESessionHijack) GetPrompts() []string {
	return []string{"Sample MCP SSE session IDs and test replay off the original TCP connection"}
}

type sseSessionClass string

const (
	sseClassBaseline         sseSessionClass = "baseline"
	sseClassNotTCPBound      sseSessionClass = "session-not-tcp-bound"
	sseClassPostCloseAlive   sseSessionClass = "session-post-close-alive"
	sseClassUnknownIDRejects sseSessionClass = "unknown-id-rejects" // control
)

// sseSample carries one sampled session's identity. The raw id and the
// live post URL are kept in memory only; anything that reaches attempt
// metadata / output goes through the redacted form (see idFingerprint
// and redactedPostURL). Fixes CodeRabbit #4 — no live bearer token in
// scanner artefacts.
type sseSample struct {
	id              string // NEVER persisted or emitted to output
	idFingerprint   string // SHA-256[:16] hex — safe correlation handle
	postURL         string // NEVER persisted or emitted
	redactedPostURL string // session_id replaced with "<redacted>"
	baseOrigin      string
}

// Probe resolves the SSE endpoint, samples N sessions, and runs the
// weakness analyses. Returns no attempts (no error) for non-SSE transports.
func (p *SSESessionHijack) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.SSESessionHijack: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	// Only SSE transport implements this session model. Streamable HTTP is
	// covered by a future probe.
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		if mcpEnd.Transport() != "" && mcpEnd.Transport() != "sse" {
			slog.Info("mcptransport.SSESessionHijack: skipping non-SSE transport", "transport", mcpEnd.Transport())
			return nil, nil
		}
	}

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}

	// Step 1: obtain ONE valid session ID via a normal SSE handshake.
	// The sample carries a close handle for the SSE stream so the Probe
	// can control the lifecycle — cross-connection replay must happen
	// with the stream STILL OPEN (that's the "different client, same
	// server view of session-active" scenario), then close, wait, and
	// run the post-close replay. Fixes CodeRabbit #2.
	sample, closeStream, sampleAttempt := p.sampleOne(ctx, client, endpoint)
	attempts := []*attempt.Attempt{sampleAttempt}
	if sample == nil {
		sampleAttempt.Metadata[attempt.MetadataKeyInconclusive] = true
		sampleAttempt.Metadata[attempt.MetadataKeyInconclusiveReason] = "SSE handshake failed — could not obtain a session ID"
		return attempts, nil
	}
	// Ensure the stream is always closed, even on early return.
	defer closeStream()

	// Step 2: control test — fabricated session id. Server should reject.
	// If it accepts, downstream replay findings would be FPs — the server
	// has no session handling at all, which the control attempt records.
	// If the control POST itself errors (network drop, transient 5xx), the
	// control is *unverified* — replays get marked inconclusive instead of
	// scoring as real findings. Fixes CodeRabbit #10.
	control, controlVerified := p.controlUnknownID(ctx, client, *sample)
	attempts = append(attempts, control)
	serverAcceptsAnyID := metaBool(control, attempt.MetadataKeySSESessionAccepted)

	proxied := p.proxyInPath(gen)
	if proxied {
		slog.Info("mcptransport.SSESessionHijack: proxy in path; connection-lifetime replay findings will be recorded as inconclusive",
			"reason", "keep-alive proxies hold SSE upstream open, making session-lifetime tests unreliable")
	}
	// Force fresh TCP conns for replays.
	replayClient := withoutKeepAlives(client)

	// Step 3a: replayCrossConnection while stream is STILL OPEN.
	// Tests "does the server bind the session to the TCP conn holding
	// the stream, or to the session_id alone?" A server that accepts
	// this POST treats the id as a naked bearer token — the primary
	// hijack primitive.
	attempts = append(attempts, p.replayCrossConnection(ctx, replayClient, *sample, serverAcceptsAnyID, controlVerified, proxied))

	// Step 3b: close the stream, wait, then replayPostClose. This tests
	// a distinct property: does the session survive stream close?
	// Without step 3a running first (while stream still open), both
	// replays would just test the same thing.
	closeStream()
	select {
	case <-ctx.Done():
		return attempts, nil
	case <-time.After(500 * time.Millisecond):
	}
	attempts = append(attempts, p.replayPostClose(ctx, replayClient, *sample, serverAcceptsAnyID, controlVerified, proxied))

	return attempts, nil
}

// proxyInPath reports whether the target generator has an explicit outbound
// proxy configured. See the comment on types.MCPEndpoint.ProxyURL for why
// only explicit proxies count.
func (p *SSESessionHijack) proxyInPath(gen types.Generator) bool {
	end, ok := gen.(types.MCPEndpoint)
	if !ok {
		return false
	}
	return end.ProxyURL() != nil
}

// withoutKeepAlives returns a shallow copy of client whose Transport is a
// clone of the original with DisableKeepAlives=true. Used for the SSE
// replay tests so each POST is guaranteed to open a fresh TCP conn from
// our side rather than relying on incidental pool eviction. If the
// Transport isn't an *http.Transport (custom impls, test recorders) we
// return the client unchanged — the S2 test then still passes because
// the recording RoundTripper is preserved.
func withoutKeepAlives(client *http.Client) *http.Client {
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		return client
	}
	cloned := tr.Clone()
	cloned.DisableKeepAlives = true
	return &http.Client{
		Transport:     cloned,
		Timeout:       client.Timeout,
		CheckRedirect: client.CheckRedirect,
	}
}

// resolveEndpoint returns the SSE endpoint from probe config or generator.
func (p *SSESessionHijack) resolveEndpoint(gen types.Generator) string {
	if p.endpointOverride != "" {
		return p.endpointOverride
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// sampleOne opens an SSE connection, reads the endpoint event to extract the
// session ID, and returns a close handle for the stream. The CALLER is
// responsible for invoking closeStream() at the right point in the probe
// lifecycle — the cross-connection replay test needs the stream still open,
// then close before the post-close replay. closeStream is idempotent and
// safe to call multiple times / from a defer.
//
// The returned sseSample's `id` and `postURL` fields hold the live
// credential in memory only. Attempt metadata and output use the
// idFingerprint (SHA-256[:16] hex) and redactedPostURL instead so the
// scan JSONL, Burp captures, and logs never persist the bearer token.
// Fixes CodeRabbit #4.
func (p *SSESessionHijack) sampleOne(ctx context.Context, client *http.Client, endpoint string) (*sseSample, func(), *attempt.Attempt) {
	noop := func() {}
	a := attempt.New("[baseline] SSE handshake — obtain session id")
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassBaseline)

	// The HTTP request lives on a child of the parent ctx so closeStream
	// can cancel it, but has NO timeout of its own — the SSE stream must
	// stay open across the control POST and cross-connection replay.
	// The first-frame read gets its own short deadline inside
	// readEndpointEvent (below) so a silent server can't block the probe.
	// Fixes CodeRabbit #11.
	streamCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		cancel()
		a.SetError(err)
		return nil, noop, a
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		cancel()
		a.SetError(err)
		return nil, noop, a
	}
	// closeStream is idempotent — see the `once` pattern below.
	var closeOnce sync.Once
	closeStream := func() {
		closeOnce.Do(func() {
			_ = resp.Body.Close()
			cancel()
		})
	}

	if resp.StatusCode != http.StatusOK {
		a.AddOutput(fmt.Sprintf("HTTP %d — server refused SSE stream", resp.StatusCode))
		a.Complete()
		closeStream()
		return nil, noop, a
	}

	sessionID, endpointPath, err := readEndpointEvent(resp.Body, 2*time.Second)
	if err != nil {
		a.SetError(err)
		closeStream()
		return nil, noop, a
	}
	postURL, err := resolvePostURL(endpoint, endpointPath)
	if err != nil {
		// A malicious or compromised MCP server can return an ABSOLUTE URL
		// in the endpoint event that points at cloud metadata, internal
		// admin endpoints, or any other host. We refuse to follow it —
		// the probe's contract is to talk to the operator-chosen target,
		// not wherever the target tells us to go.
		a.SetError(fmt.Errorf("refusing off-host endpoint URL: %w", err))
		closeStream()
		return nil, noop, a
	}
	// Redact live credential before it touches metadata or output.
	fingerprint := fingerprintID(sessionID)
	redacted := redactSessionID(postURL)
	a.Metadata[attempt.MetadataKeySSESessionSample] = fingerprint
	a.Metadata[attempt.MetadataKeySSESessionEndpoint] = redacted
	a.AddOutput(fmt.Sprintf("session_id=<fp:%s> post_url=%s", fingerprint, redacted))
	a.Complete()

	return &sseSample{
		id:              sessionID,
		idFingerprint:   fingerprint,
		postURL:         postURL,
		redactedPostURL: redacted,
		baseOrigin:      endpoint,
	}, closeStream, a
}

// fingerprintID returns a stable 16-hex correlation handle derived from the
// session id, without carrying any bytes of the live credential. Two attempts
// against the same session share a fingerprint; the fingerprint is not
// reversible to the id.
func fingerprintID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:8])
}

// redactSessionID replaces the session_id query parameter's value with the
// literal string "<redacted>" so logs / reports / Burp captures don't retain
// the live bearer token.
func redactSessionID(postURL string) string {
	u, err := url.Parse(postURL)
	if err != nil {
		return "<unparseable>"
	}
	q := u.Query()
	if q.Get("session_id") != "" {
		q.Set("session_id", "<redacted>")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// controlUnknownID is a control test: post a made-up session ID and confirm
// the server rejects it. Without this control, the replay tests below are
// inconclusive — a server that accepts EVERY POST regardless of session id
// is broken but not specifically a session-replay finding.
//
// The second return is `verified`: true when the control POST completed and
// the server's response was actually classified (accept or reject); false
// when the POST errored (network drop, transient 5xx) and we don't actually
// know how the server handles unknown IDs. An unverified control means the
// caller must not score subsequent replay findings as real — they get
// marked inconclusive instead. Fixes CodeRabbit #10.
func (p *SSESessionHijack) controlUnknownID(ctx context.Context, client *http.Client, ref sseSample) (*attempt.Attempt, bool) {
	fakeID := "AUGCONTROL" + randToken()
	fakeURL := replaceSessionID(ref.postURL, fakeID)
	a := attempt.New(fmt.Sprintf("[%s] POST with fabricated id", sseClassUnknownIDRejects))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassUnknownIDRejects)
	// The fabricated id is safe to persist (it's ours), but we still
	// avoid emitting the redacted-for-consistency path.
	a.Metadata[attempt.MetadataKeySSESessionSample] = "AUGCONTROL<fabricated>"

	status, body, err := p.postInitialize(ctx, client, fakeURL)
	if err != nil {
		a.SetError(err)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("unknown-id control POST failed — replay verdicts unverified: %v", err)
		return a, false
	}
	a.AddOutput(fmt.Sprintf("HTTP %d\n%s", status, truncBody(body)))
	accepted := serverAcceptedPOST(status, body)
	// A rejection is the *expected* outcome — accepted=false means
	// "no anomaly." When the server accepts an unknown id we record
	// accepted=true so the replay tests know to suppress themselves.
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = accepted
	a.Complete()
	return a, true
}

// serverAcceptedPOST classifies a response to a session-scoped POST by
// whether the server ACCEPTED the request (understood the session and
// processed the message) vs REJECTED it (at HTTP layer or inside the
// JSON-RPC envelope). Fixes CodeRabbit #3.
//
// Accepted signals:
//   - HTTP 202 with empty body (canonical FastMCP behaviour: message
//     accepted, response will come back on the SSE stream)
//   - HTTP 2xx with a JSON-RPC 2.0 envelope carrying a "result" field
//
// Rejected signals:
//   - HTTP 4xx / 5xx
//   - HTTP 2xx with a JSON-RPC 2.0 envelope carrying an "error" field
//     (server understood the request but refused it at the RPC layer —
//     e.g. "session expired", "unknown method")
//   - HTTP 2xx with a non-JSON-RPC-shaped body (server responded with
//     something we can't classify as an acceptance)
func serverAcceptedPOST(status int, body string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		// FastMCP's happy path: 202 Accepted with empty body.
		return true
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
		return false
	}
	if envelope.JSONRPC != "2.0" {
		return false
	}
	if len(envelope.Error) > 0 {
		// JSON-RPC error envelope — server engaged but refused.
		return false
	}
	return len(envelope.Result) > 0
}

// replayCrossConnection tests whether a session ID captured from one stream
// can be used from an entirely fresh HTTP client (different TCP connection,
// no held stream). This is the primary hijack primitive: an off-path
// attacker who obtains the ID can drive the session. When
// serverAcceptsAnyID=true (the control test showed the server accepts a
// fabricated id) the finding is suppressed regardless of outcome — the
// server has no session enforcement at all, which is a different (broader)
// bug the control attempt already carries.
func (p *SSESessionHijack) replayCrossConnection(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID, controlVerified, proxied bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] POST from fresh TCP conn — stream still open", sseClassNotTCPBound))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassNotTCPBound)
	a.Metadata[attempt.MetadataKeySSESessionSample] = ref.idFingerprint

	status, body, err := p.postInitialize(ctx, client, ref.postURL)
	if err != nil {
		a.SetError(err)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("replay POST failed: %v", err)
		return a
	}
	accepted := serverAcceptedPOST(status, body)
	switch {
	case serverAcceptsAnyID:
		accepted = false
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
	case accepted && !controlVerified:
		a.AddOutput("[inconclusive — unknown-id control failed; cannot verify the server actually distinguishes valid from invalid ids]\n")
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "control-not-verified: unknown-id control POST errored, so an accept-any-id server may look like a real replay finding"
	case proxied && accepted:
		a.AddOutput("[inconclusive — outbound proxy configured; a keep-alive proxy holds the SSE conn open upstream, so the server may see the session as active regardless of the target's own session model]\n")
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "proxy-in-path: cannot distinguish target session model from keepalive proxy behaviour"
	}
	a.AddOutput(fmt.Sprintf("HTTP %d\n%s", status, truncBody(body)))
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = accepted
	a.Complete()
	return a
}

// replayPostClose runs AFTER the SSE stream has been closed by the caller
// (Probe orchestrates the close between the cross-connection replay and
// this one — see the type-doc flow). If the server still accepts a POST
// bearing the sampled session id, the id has outlived its stream: the
// session survives its stream lifetime (CWE-613). Same control-suppression
// rule as replayCrossConnection.
func (p *SSESessionHijack) replayPostClose(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID, controlVerified, proxied bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] POST after stream close + 500ms grace", sseClassPostCloseAlive))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassPostCloseAlive)
	a.Metadata[attempt.MetadataKeySSESessionSample] = ref.idFingerprint

	status, body, err := p.postInitialize(ctx, client, ref.postURL)
	if err != nil {
		a.SetError(err)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("post-close replay POST failed: %v", err)
		return a
	}
	accepted := serverAcceptedPOST(status, body)
	switch {
	case serverAcceptsAnyID:
		accepted = false
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
	case accepted && !controlVerified:
		a.AddOutput("[inconclusive — unknown-id control failed; cannot verify the server actually distinguishes valid from invalid ids]\n")
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "control-not-verified: unknown-id control POST errored, so an accept-any-id server may look like a real replay finding"
	case proxied && accepted:
		a.AddOutput("[inconclusive — outbound proxy configured; upstream conn survives our FIN so server may still see the session]\n")
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "proxy-in-path: keepalive upstream survives client FIN"
	}
	a.AddOutput(fmt.Sprintf("HTTP %d\n%s", status, truncBody(body)))
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = accepted
	a.Complete()
	return a
}

// postInitialize sends an MCP initialize JSON-RPC to the given URL and
// returns the response status + a bounded body.
func (p *SSESessionHijack) postInitialize(ctx context.Context, client *http.Client, postURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewBufferString(mcpInitializePayload))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	return resp.StatusCode, string(body), nil
}

// borrowHTTPClient returns the generator's anonymous http.Client (proxy +
// TLS inherited, but NO auth/scan-tag headers) with this probe's per-run
// overrides. The hijack scenario models an off-path attacker who intercepts
// a session id (log leak, referer, browser history) but does NOT hold the
// operator's bearer token; sending the token would invert the verdict on
// an authenticated server. See OriginValidation.borrowHTTPClient for the
// fallback rationale when the target does not expose types.MCPEndpoint.
func (p *SSESessionHijack) borrowHTTPClient(gen types.Generator) (*http.Client, error) {
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

// readEndpointEvent reads SSE frames from body until it finds an
// `event: endpoint` block, and returns the session id + full data value.
// Returns an error if no endpoint event arrives before the deadline.
func readEndpointEvent(body io.Reader, deadline time.Duration) (string, string, error) {
	// The endpoint frame arrives immediately after the server flushes; we
	// don't need to consume the whole stream. Buffer just enough to find
	// two newlines (an SSE frame boundary).
	deadlineCh := time.After(deadline)
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), 32*1024)

	type result struct {
		id, path string
		err      error
	}
	ch := make(chan result, 1)
	go func() {
		var eventName, dataLine string
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event:"):
				eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			case line == "":
				// Blank line = end of frame. If this frame was the
				// endpoint event we care about, capture it; otherwise
				// discard. State MUST reset unconditionally so a
				// data-less keepalive frame ("event: ping\n\n") doesn't
				// leak `eventName` into the next frame's context.
				if eventName == "endpoint" && dataLine != "" {
					id := extractSessionID(dataLine)
					ch <- result{id: id, path: dataLine}
					return
				}
				eventName, dataLine = "", ""
			}
		}
		ch <- result{err: fmt.Errorf("no endpoint event; stream closed")}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return "", "", r.err
		}
		if r.id == "" {
			return "", "", fmt.Errorf("endpoint event carried no session_id (data=%q)", r.path)
		}
		return r.id, r.path, nil
	case <-deadlineCh:
		return "", "", fmt.Errorf("timed out waiting for endpoint event")
	}
}

// extractSessionID pulls the session_id query param out of an SSE endpoint
// data payload like `/messages/?session_id=abc123`.
func extractSessionID(dataLine string) string {
	if idx := strings.Index(dataLine, "session_id="); idx >= 0 {
		rest := dataLine[idx+len("session_id="):]
		if amp := strings.Index(rest, "&"); amp >= 0 {
			return rest[:amp]
		}
		return rest
	}
	return ""
}

// resolvePostURL merges the SSE base URL with the endpoint-frame path from
// the target and returns the fully-qualified URL to POST to. It REFUSES a
// resolved URL whose scheme or host differs from the base — a malicious MCP
// server could otherwise redirect the probe to 169.254.169.254, an internal
// admin endpoint, or downgrade https→http. Returns ("", err) on any
// mismatch; callers MUST treat the error as a hard stop.
func resolvePostURL(base, endpointPath string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base %q: %w", base, err)
	}
	rel, err := url.Parse(endpointPath)
	if err != nil {
		return "", fmt.Errorf("parse endpoint path %q: %w", endpointPath, err)
	}
	resolved := b.ResolveReference(rel)
	if resolved.Scheme != b.Scheme || resolved.Host != b.Host {
		return "", fmt.Errorf("resolved URL %q leaves base host (expected %s://%s, got %s://%s)",
			resolved.String(), b.Scheme, b.Host, resolved.Scheme, resolved.Host)
	}
	return resolved.String(), nil
}

// replaceSessionID substitutes a new session id into a URL, keeping other
// query params intact.
func replaceSessionID(postURL, newID string) string {
	u, err := url.Parse(postURL)
	if err != nil {
		return postURL
	}
	q := u.Query()
	q.Set("session_id", newID)
	u.RawQuery = q.Encode()
	return u.String()
}

// truncBody bounds body previews in probe output.
func truncBody(body string) string {
	if len(body) <= 512 {
		return body
	}
	return body[:512] + "…"
}

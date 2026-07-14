package toolsec

import (
	"bufio"
	"bytes"
	"context"
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
	probes.Register("toolsec.SSESessionHijack", NewSSESessionHijack)
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
// The probe does two things with ONE valid session ID it obtains via a
// normal SSE handshake:
//
//  1. Shape-sniffs the ID — length + character-set diversity. A single
//     sample can't statistically audit an RNG (that would need ~2^64
//     samples to detect a 128-bit collision), but it CAN catch the
//     obviously-guessable cases: short IDs, all-digit / all-lowercase-alpha
//     IDs, timestamp-shaped IDs. That's the actual failure mode for weak
//     session generation — not statistically-imperfect randomness.
//
//  2. Session-replay tests — take the ID, close the SSE stream, POST to
//     the session's endpoint from a fresh TCP connection. If the server
//     accepts, the ID is a naked bearer token with no client binding
//     (CWE-287). Also tested after a post-close delay (CWE-613:
//     session outlives its stream).
//
// What the probe does NOT do: multi-sample entropy analysis, prefix
// clustering, birthday-collision detection. Those were retired as
// statistically impossible to run at any N a scanner can afford; the
// real signals for weak session IDs are shape, not entropy.
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

func (p *SSESessionHijack) Name() string { return "toolsec.SSESessionHijack" }

func (p *SSESessionHijack) Description() string {
	return "Tests MCP SSE session-management for hijack primitives: obtains one valid session ID, shape-sniffs it for short/low-diversity/timestamp-shape (the guessable failure modes), then replays it off the original TCP connection and after stream close. Statistical RNG audit is deliberately not attempted — no realistic sample count could detect predictability of a 128-bit space."
}

func (p *SSESessionHijack) Goal() string {
	return "Determine whether a session ID obtained via any means (leak, log, referer, DNS rebind) is a naked bearer token — reusable off the TCP connection that created it, or surviving past its stream. Also flag obviously-guessable ID shapes."
}

func (p *SSESessionHijack) GetPrimaryDetector() string { return "toolsec.SSESessionHijack" }

func (p *SSESessionHijack) GetPrompts() []string {
	return []string{"Sample MCP SSE session IDs and test replay off the original TCP connection"}
}

type sseSessionClass string

const (
	sseClassBaseline         sseSessionClass = "baseline"
	sseClassShort            sseSessionClass = "session-id-short"
	sseClassLowDiversity     sseSessionClass = "session-id-low-diversity"
	sseClassGuessableShape   sseSessionClass = "session-id-guessable-shape"
	sseClassNotTCPBound      sseSessionClass = "session-not-tcp-bound"
	sseClassPostCloseAlive   sseSessionClass = "session-post-close-alive"
	sseClassUnknownIDRejects sseSessionClass = "unknown-id-rejects" // control
)

// sseSample carries one sampled session's identity — the id itself, the POST
// endpoint the server advertised for it, and the base URL the sample was
// taken from (needed to resolve the relative endpoint later).
type sseSample struct {
	id         string
	postURL    string // fully-qualified URL to POST to for this session
	baseOrigin string
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
		return nil, fmt.Errorf("toolsec.SSESessionHijack: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	// Only SSE transport implements this session model. Streamable HTTP is
	// covered by a future probe.
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		if mcpEnd.Transport() != "" && mcpEnd.Transport() != "sse" {
			slog.Info("toolsec.SSESessionHijack: skipping non-SSE transport", "transport", mcpEnd.Transport())
			return nil, nil
		}
	}

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}

	// Step 1: obtain ONE valid session ID via a normal SSE handshake.
	// One sample is sufficient for both branches of this probe: the
	// shape-sniff runs on a single ID, and the replay tests only need
	// one valid ID to reuse. Additional samples would be latency for
	// no additional information — see the type doc.
	sample, sampleAttempt := p.sampleOne(ctx, client, endpoint)
	attempts := []*attempt.Attempt{sampleAttempt}
	if sample == nil {
		// Sampling failed → nothing to classify or replay against.
		// The sampleAttempt already carries the error, but mark it
		// inconclusive so the detector doesn't ship a green SAFE
		// verdict for a target we couldn't actually reach.
		sampleAttempt.Metadata[attempt.MetadataKeyInconclusive] = true
		sampleAttempt.Metadata[attempt.MetadataKeyInconclusiveReason] = "SSE handshake failed — could not obtain a session ID"
		return attempts, nil
	}

	// Step 2: shape-sniff the ID.
	attempts = append(attempts, p.classifyID(sample.id)...)

	// Step 3: replay tests. Two independent suppressions apply:
	//   (a) if the target accepts a FABRICATED session id, the server
	//       has no session handling at all and the replay tests would
	//       be false positives (they'd re-confirm the same broken
	//       behaviour). Marked accepted=false; the control attempt
	//       itself carries the finding.
	//   (b) if an explicit outbound proxy is configured on the target
	//       generator, the "distinct client" property the replay
	//       tests claim to measure is compromised at the proxy layer,
	//       not the server. Marked inconclusive; the reviewer must
	//       confirm out-of-band.
	control := p.controlUnknownID(ctx, client, *sample)
	attempts = append(attempts, control)
	serverAcceptsAnyID := metaBool(control, attempt.MetadataKeySSESessionAccepted)
	proxied := p.proxyInPath(gen)
	if proxied {
		slog.Info("toolsec.SSESessionHijack: proxy in path; connection-lifetime replay findings will be recorded as inconclusive",
			"reason", "keep-alive proxies hold SSE upstream open, making session-lifetime tests unreliable")
	}
	// Force fresh TCP conns for replays (see withoutKeepAlives).
	replayClient := withoutKeepAlives(client)
	attempts = append(attempts, p.replayCrossConnection(ctx, replayClient, *sample, serverAcceptsAnyID, proxied))
	attempts = append(attempts, p.replayPostClose(ctx, replayClient, *sample, serverAcceptsAnyID, proxied))

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
// session ID, then closes the stream. Returns (nil, attempt) on any failure.
func (p *SSESessionHijack) sampleOne(ctx context.Context, client *http.Client, endpoint string) (*sseSample, *attempt.Attempt) {
	a := attempt.New("[baseline] SSE handshake — obtain session id")
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassBaseline)

	// Short deadline: we only need the FIRST event frame.
	sampleCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(sampleCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		a.SetError(err)
		return nil, a
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		a.SetError(err)
		return nil, a
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.AddOutput(fmt.Sprintf("HTTP %d — server refused SSE stream", resp.StatusCode))
		a.Complete()
		return nil, a
	}

	sessionID, endpointPath, err := readEndpointEvent(resp.Body, 2*time.Second)
	if err != nil {
		a.SetError(err)
		return nil, a
	}
	postURL, err := resolvePostURL(endpoint, endpointPath)
	if err != nil {
		// A malicious or compromised MCP server can return an ABSOLUTE URL
		// in the endpoint event that points at cloud metadata, internal
		// admin endpoints, or any other host. We refuse to follow it —
		// the probe's contract is to talk to the operator-chosen target,
		// not wherever the target tells us to go.
		a.SetError(fmt.Errorf("refusing off-host endpoint URL: %w", err))
		return nil, a
	}
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(sessionID)
	a.Metadata[attempt.MetadataKeySSESessionEndpoint] = postURL
	a.AddOutput(fmt.Sprintf("session_id=%s post_url=%s", truncID(sessionID), postURL))
	a.Complete()

	return &sseSample{id: sessionID, postURL: postURL, baseOrigin: endpoint}, a
}

// classifyID shape-sniffs a single session ID for the three failure modes a
// single sample can reliably surface. Statistical RNG audit is deliberately
// not attempted (see the type doc): a scanner cannot afford the ~2^64
// samples that would be needed to detect a 128-bit-collision-space weakness,
// so we only flag things that ARE obvious from one ID.
func (p *SSESessionHijack) classifyID(id string) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	// Class: too short. 16 chars ≈ 64 bits at 4 bits/char (uniform hex).
	// Below this a session id is guessable given enough attempts against
	// the server, independent of the RNG's quality.
	if len(id) < 16 {
		a := p.classAttempt(sseClassShort, fmt.Sprintf("id is %d chars (< 16)", len(id)), id)
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	// Class: low character-set diversity. Distinct-chars / length ratio:
	// a random 32-hex UUID scores ~0.5 (16 unique hex chars in 32
	// positions). Something like "000000000000000000000000000abc" scores
	// close to 0.1 — obviously not fit-for-purpose. This is a shape
	// property of the ONE id, not a statistical claim about the RNG.
	if diversity := charDiversity(id); diversity < 0.25 && len(id) > 0 {
		a := p.classAttempt(sseClassLowDiversity,
			fmt.Sprintf("id uses %d distinct chars in %d positions (diversity %.2f, < 0.25)", uniqueChars(id), len(id), diversity),
			id)
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	// Class: guessable shape. Catches obviously-non-random patterns from
	// a single sample: all digits (counter or timestamp), plausible unix
	// timestamp value, all lowercase alpha with no digits, etc.
	if reason, ok := guessableShape(id); ok {
		a := p.classAttempt(sseClassGuessableShape, reason, id)
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	return attempts
}

// charDiversity is (unique chars) / (length). Random hex → ~0.5; random
// alphanumeric → ~0.9; a repetitive or narrow-alphabet id → close to 0.
func charDiversity(s string) float64 {
	if s == "" {
		return 0
	}
	return float64(uniqueChars(s)) / float64(len(s))
}

func uniqueChars(s string) int {
	seen := make(map[byte]struct{}, len(s))
	for i := 0; i < len(s); i++ {
		seen[s[i]] = struct{}{}
	}
	return len(seen)
}

// guessableShape returns a reason string + true when the id matches an
// obviously-guessable pattern. Kept intentionally strict — this only fires
// on IDs that couldn't POSSIBLY be from a CSPRNG, so false-positive rate
// against real MCP servers should be ~0.
func guessableShape(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	// All decimal digits: counter, unix timestamp, or a numeric-only id.
	allDigits := true
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return fmt.Sprintf("id is all decimal digits (%d chars) — counter or timestamp shape, not a CSPRNG output", len(id)), true
	}
	// All lowercase letters, no digits: dictionary word or narrow alphabet.
	if len(id) >= 4 {
		allLowerAlpha := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			if c < 'a' || c > 'z' {
				allLowerAlpha = false
				break
			}
		}
		if allLowerAlpha {
			return fmt.Sprintf("id is %d lowercase letters with no digits — narrow alphabet, likely not from a CSPRNG", len(id)), true
		}
	}
	return "", false
}

// classAttempt builds an attempt carrying a classification tag.
func (p *SSESessionHijack) classAttempt(class sseSessionClass, note, id string) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] %s", class, note))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(class)
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(id)
	a.AddOutput(note)
	a.Complete()
	return a
}

// controlUnknownID is a control test: post a made-up session ID and confirm
// the server rejects it. Without this control, the replay tests below are
// inconclusive — a server that accepts EVERY POST regardless of session id
// is broken but not specifically a session-replay finding.
func (p *SSESessionHijack) controlUnknownID(ctx context.Context, client *http.Client, ref sseSample) *attempt.Attempt {
	fakeID := "AUGCONTROL" + randToken()
	fakeURL := replaceSessionID(ref.postURL, fakeID)
	a := attempt.New(fmt.Sprintf("[%s] POST with fabricated id", sseClassUnknownIDRejects))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassUnknownIDRejects)
	a.Metadata[attempt.MetadataKeySSESessionSample] = fakeID

	status, body, err := p.postInitialize(ctx, client, fakeURL)
	if err != nil {
		a.SetError(err)
		return a
	}
	rejected := status >= 400
	a.AddOutput(fmt.Sprintf("HTTP %d\n%s", status, truncBody(body)))
	// A rejection is the *expected* outcome — we record it as "accepted:
	// false" meaning "no anomaly." When the server accepts an unknown id we
	// record "accepted: true" as an informational anomaly (the downstream
	// replay findings would be false positives without this check, so the
	// detector will see it and know to suppress).
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = !rejected
	a.Complete()
	return a
}

// replayCrossConnection tests whether a session ID captured from one stream
// can be used from an entirely fresh HTTP client (different TCP connection,
// no held stream). This is the primary hijack primitive: an off-path
// attacker who obtains the ID can drive the session. When
// serverAcceptsAnyID=true (the control test showed the server accepts a
// fabricated id) the finding is suppressed regardless of outcome — the
// server has no session enforcement at all, which is a different (broader)
// bug the control attempt already carries.
func (p *SSESessionHijack) replayCrossConnection(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID, proxied bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] POST from fresh TCP conn with sampled id", sseClassNotTCPBound))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassNotTCPBound)
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(ref.id)

	// `client` was built with DisableKeepAlives=true (see
	// withoutKeepAlives), so this POST opens a fresh TCP conn from us by
	// construction. Whether the SERVER still sees the session as alive
	// depends on whether an intermediary proxy held the upstream open on
	// our behalf — the `proxied` guard below marks that case inconclusive.
	status, body, err := p.postInitialize(ctx, client, ref.postURL)
	if err != nil {
		// A transient network error during the replay POST leaves us
		// unable to decide SAFE/VULN. Mark inconclusive rather than
		// letting the SetError → default 0.0 pathway ship a green
		// verdict for a target we didn't actually reach. Mauro S4.
		a.SetError(err)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("replay POST failed: %v", err)
		return a
	}
	accepted := status >= 200 && status < 400
	switch {
	case serverAcceptsAnyID:
		accepted = false // suppressed — server accepts everything
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
	case proxied && accepted:
		// Do NOT force accepted=false — that would ship a green SAFE
		// verdict on a target we couldn't actually assess. Instead
		// leave accepted as-observed and set the inconclusive flag so
		// the detector emits a non-zero "needs manual confirmation"
		// score. See feedback on PR #234 (Mauro B2).
		a.AddOutput("[inconclusive — outbound proxy configured; a keep-alive proxy holds the SSE conn open upstream, so the server may see the session as active regardless of the target's own session model]\n")
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = "proxy-in-path: cannot distinguish target session model from keepalive proxy behaviour"
	}
	a.AddOutput(fmt.Sprintf("HTTP %d\n%s", status, truncBody(body)))
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = accepted
	a.Complete()
	return a
}

// replayPostClose is the same shape but waits before the POST, ensuring the
// original SSE stream is fully torn down. A server that still accepts the
// POST is treating the session ID as a naked bearer token with no TTL bound
// to stream lifetime. Same control-suppression rule as replayCrossConnection.
func (p *SSESessionHijack) replayPostClose(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID, proxied bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] POST after stream close + delay", sseClassPostCloseAlive))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassPostCloseAlive)
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(ref.id)

	// A short delay lets the server observe the FIN and clean up any TCP-
	// bound state. 500 ms is a lot longer than any garbage-collect debounce.
	select {
	case <-ctx.Done():
		a.SetError(ctx.Err())
		return a
	case <-time.After(500 * time.Millisecond):
	}

	// The generator's client returns a fresh instance each call; we don't
	// share connection pool state with the SSE stream (which we closed after
	// reading the endpoint frame). No need to disable keepalives — the SSE
	// conn has already been evicted from the pool, so this POST opens a new
	// TCP conn to the target (or to the proxy, if one is configured).
	status, body, err := p.postInitialize(ctx, client, ref.postURL)
	if err != nil {
		a.SetError(err)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("post-close replay POST failed: %v", err)
		return a
	}
	accepted := status >= 200 && status < 400
	switch {
	case serverAcceptsAnyID:
		accepted = false
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
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
	defer resp.Body.Close()
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

// truncID returns the first 24 chars of an id so long tokens don't drown
// output; if the id is shorter it's returned unchanged.
func truncID(id string) string {
	if len(id) <= 24 {
		return id
	}
	return id[:24] + "…"
}

// truncBody bounds body previews in probe output.
func truncBody(body string) string {
	if len(body) <= 512 {
		return body
	}
	return body[:512] + "…"
}

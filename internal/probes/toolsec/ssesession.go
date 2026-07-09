package toolsec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
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

// SSESessionHijack tests the legacy MCP SSE transport for two independent
// classes of session-management weakness:
//
//  1. Session-ID quality — sample N session IDs and inspect them for length,
//     entropy, shared prefixes, and collision. Any of these weaknesses makes
//     a session guessable by an off-path attacker without having to intercept
//     the SSE stream.
//
//  2. Session lifetime — a well-behaved SSE server invalidates a session
//     when its stream disconnects and rejects POSTs from any TCP connection
//     other than the one holding the stream. FastMCP-style servers commonly
//     do neither; the session is a naked bearer token that any HTTP client
//     with the ID can drive until server-side GC. This is a real hijack
//     primitive when the ID leaks (referer, logs, browser history, DNS
//     rebinding, exposed proxies).
//
// The probe targets only SSE transports; streamable HTTP has a different
// session model (Mcp-Session-Id header) covered by a future probe.
type SSESessionHijack struct {
	endpointOverride   string
	sampleCount        int
	insecureSkipVerify bool
	timeout            time.Duration
}

// NewSSESessionHijack constructs the probe.
func NewSSESessionHijack(cfg registry.Config) (probes.Prober, error) {
	return &SSESessionHijack{
		endpointOverride:   registry.GetString(cfg, "endpoint", ""),
		sampleCount:        registry.GetInt(cfg, "sample_count", 6),
		insecureSkipVerify: registry.GetBool(cfg, "insecure_skip_verify", false),
		timeout:            time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
	}, nil
}

func (p *SSESessionHijack) Name() string { return "toolsec.SSESessionHijack" }

func (p *SSESessionHijack) Description() string {
	return "Samples MCP SSE session IDs, inspects them for short length / low entropy / shared prefixes / collision, and tests whether the server accepts POSTs to a session's endpoint from a fresh TCP connection or after the stream closed"
}

func (p *SSESessionHijack) Goal() string {
	return "Determine whether the MCP SSE transport's session tokens are predictable, or whether a stolen session ID can be replayed off the original TCP connection"
}

func (p *SSESessionHijack) GetPrimaryDetector() string { return "toolsec.SSESessionHijack" }

func (p *SSESessionHijack) GetPrompts() []string {
	return []string{"Sample MCP SSE session IDs and test replay off the original TCP connection"}
}

type sseSessionClass string

const (
	sseClassBaseline         sseSessionClass = "baseline"
	sseClassShort            sseSessionClass = "session-id-short"
	sseClassLowEntropy       sseSessionClass = "session-id-low-entropy"
	sseClassCommonPrefix     sseSessionClass = "session-id-common-prefix"
	sseClassCollision        sseSessionClass = "session-id-collision"
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

	client := p.newHTTPClient()

	// Step 1: sample N sessions.
	samples := make([]sseSample, 0, p.sampleCount)
	var sampleAttempts []*attempt.Attempt
	for i := 0; i < p.sampleCount; i++ {
		s, sampleAttempt := p.sampleOne(ctx, client, endpoint, i)
		sampleAttempts = append(sampleAttempts, sampleAttempt)
		if s != nil {
			samples = append(samples, *s)
		}
	}
	if len(samples) < 2 {
		slog.Warn("toolsec.SSESessionHijack: too few session samples for analysis", "got", len(samples))
		return sampleAttempts, nil
	}

	attempts := sampleAttempts

	// Step 2: session-ID weakness classes.
	attempts = append(attempts, p.classifySamples(samples)...)

	// Step 3: replay tests using the FIRST sample. We use the first because
	// it's the earliest-captured; if any session is guaranteed to have been
	// "cleanly closed" by our client it's this one.
	//
	// The control test runs first. If it shows the server accepts a
	// fabricated id, the replay tests would be false positives (they'd
	// merely re-confirm the same broken behaviour), so we suppress them by
	// passing serverAcceptsAnyID=true into the replay methods.
	target := samples[0]
	control := p.controlUnknownID(ctx, client, target)
	attempts = append(attempts, control)
	serverAcceptsAnyID := metaBool(control, attempt.MetadataKeySSESessionAccepted)
	attempts = append(attempts, p.replayCrossConnection(ctx, client, target, serverAcceptsAnyID))
	attempts = append(attempts, p.replayPostClose(ctx, client, target, serverAcceptsAnyID))

	return attempts, nil
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
func (p *SSESessionHijack) sampleOne(ctx context.Context, client *http.Client, endpoint string, idx int) (*sseSample, *attempt.Attempt) {
	a := attempt.New(fmt.Sprintf("[baseline] sample session #%d", idx+1))
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
	postURL := resolvePostURL(endpoint, endpointPath)
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(sessionID)
	a.Metadata[attempt.MetadataKeySSESessionEndpoint] = postURL
	a.AddOutput(fmt.Sprintf("session_id=%s post_url=%s", truncID(sessionID), postURL))
	a.Complete()

	return &sseSample{id: sessionID, postURL: postURL, baseOrigin: endpoint}, a
}

// classifySamples inspects the collected session IDs for weakness classes
// and returns one attempt per class it fires.
func (p *SSESessionHijack) classifySamples(samples []sseSample) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	ids := make([]string, len(samples))
	for i, s := range samples {
		ids[i] = s.id
	}

	// Class: too short (< 16 chars ≈ 64 bits at 4 bits/char).
	minLen := len(ids[0])
	for _, id := range ids {
		if len(id) < minLen {
			minLen = len(id)
		}
	}
	if minLen < 16 {
		a := p.classAttempt(sseClassShort, fmt.Sprintf("shortest sampled id was %d chars (<16)", minLen), ids[0])
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	// Class: low entropy — Shannon over the concatenated bytes.
	bitsPerChar := shannonBitsPerChar(strings.Join(ids, ""))
	if bitsPerChar < 3.0 {
		a := p.classAttempt(sseClassLowEntropy, fmt.Sprintf("~%.2f bits/char across %d ids (weak)", bitsPerChar, len(ids)), ids[0])
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	// Class: shared prefix > 8 chars across all samples.
	prefix := longestCommonPrefix(ids)
	if len(prefix) > 8 {
		a := p.classAttempt(sseClassCommonPrefix, fmt.Sprintf("shared prefix %q (%d chars)", prefix, len(prefix)), ids[0])
		a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
		attempts = append(attempts, a)
	}

	// Class: collision (two samples equal).
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			a := p.classAttempt(sseClassCollision, fmt.Sprintf("duplicate id %q across %d samples", truncID(id), len(ids)), id)
			a.Metadata[attempt.MetadataKeySSESessionAccepted] = true
			attempts = append(attempts, a)
			break
		}
		seen[id] = true
	}

	return attempts
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
func (p *SSESessionHijack) replayCrossConnection(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] POST from fresh TCP conn with sampled id", sseClassNotTCPBound))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeySSESessionClass] = string(sseClassNotTCPBound)
	a.Metadata[attempt.MetadataKeySSESessionSample] = truncID(ref.id)

	freshClient := p.newHTTPClient()
	freshClient.Transport.(*http.Transport).DisableKeepAlives = true

	status, body, err := p.postInitialize(ctx, freshClient, ref.postURL)
	if err != nil {
		a.SetError(err)
		return a
	}
	accepted := status >= 200 && status < 400
	if serverAcceptsAnyID {
		accepted = false // suppressed — server accepts everything
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
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
func (p *SSESessionHijack) replayPostClose(ctx context.Context, client *http.Client, ref sseSample, serverAcceptsAnyID bool) *attempt.Attempt {
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

	freshClient := p.newHTTPClient()
	freshClient.Transport.(*http.Transport).DisableKeepAlives = true

	status, body, err := p.postInitialize(ctx, freshClient, ref.postURL)
	if err != nil {
		a.SetError(err)
		return a
	}
	accepted := status >= 200 && status < 400
	if serverAcceptsAnyID {
		accepted = false
		a.AddOutput("[suppressed by unknown-id control: server accepts any session id]\n")
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

// newHTTPClient builds the client used for probes.
func (p *SSESessionHijack) newHTTPClient() *http.Client {
	tr := &http.Transport{
		// #nosec G402 -- insecure_skip_verify opt-in for lab targets.
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
			if strings.HasPrefix(line, "event:") {
				eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			} else if line == "" && eventName != "" && dataLine != "" {
				if eventName == "endpoint" {
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

// resolvePostURL merges the SSE base URL with the endpoint frame path so we
// have a fully-qualified URL for the POST replay tests.
func resolvePostURL(base, endpointPath string) string {
	u, err := url.Parse(base)
	if err != nil {
		return endpointPath
	}
	rel, err := url.Parse(endpointPath)
	if err != nil {
		return endpointPath
	}
	return u.ResolveReference(rel).String()
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

// shannonBitsPerChar computes the average Shannon entropy across the byte
// distribution of a string, in bits/char. High-entropy IDs (hex UUIDs,
// base62 tokens) yield ~3.5–5.5. Sub-3.0 indicates either a very narrow
// character set or heavy repetition.
func shannonBitsPerChar(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]int, 64)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// longestCommonPrefix returns the longest prefix shared by every string.
func longestCommonPrefix(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	prefix := ss[0]
	for _, s := range ss[1:] {
		max := len(prefix)
		if len(s) < max {
			max = len(s)
		}
		i := 0
		for i < max && prefix[i] == s[i] {
			i++
		}
		prefix = prefix[:i]
		if prefix == "" {
			break
		}
	}
	return prefix
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

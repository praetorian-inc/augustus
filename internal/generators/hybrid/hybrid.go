// This file implements hybrid.Hybrid, a choreography-driven generator that
// mixes HTTP requests and a graphql-transport-ws WebSocket session.
//
// Some LLM front ends split the request and response across transports: the
// prompt is delivered by an HTTP mutation while the answer streams back over a
// WebSocket subscription (e.g. GraphQL chat UIs). A plain generator cannot drive
// these because the two halves must be interleaved in a specific order — open
// and subscribe the socket *before* posting the prompt, or the backend has no
// stream to attach the reply to.
//
// Hybrid models the exchange as an ordered list of steps (HTTP requests and
// ws_connect/ws_send/ws_await/ws_stream actions) with named value capture and
// substitution between them. This expresses any request/response transport
// pairing without target-specific code. See hybrid_config.go for the schema.
package hybrid

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/praetorian-inc/augustus/internal/generators/wsutil"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/hooks"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	generators.Register("hybrid.Hybrid", NewHybrid)
}

// Compile-time interface assertions.
var (
	_ generators.Generator      = (*Hybrid)(nil)
	_ hooks.RawResponseProvider = (*Hybrid)(nil)
)

// Hybrid is the choreography-driven HTTP+WebSocket generator.
type Hybrid struct {
	types.UsageCounter // embedded but never incremented: these endpoints report no token usage.

	cfg      HybridConfig
	client   *http.Client
	proxyURL *url.URL // optional CONNECT proxy for the WS leg (HTTP leg uses client transport)
	limiter  *ratelimit.Limiter

	// callMu serializes whole pipelines in persistent mode. The scanner shares one
	// generator instance across concurrent probe goroutines; a persistent session
	// is a single stateful WS connection, and x/net/websocket is not safe for
	// concurrent Send/Receive. Holding callMu for the duration of a pipeline keeps
	// turns sequential (and makes first-call initialization race-free).
	callMu sync.Mutex

	mu          sync.Mutex
	conn        *websocket.Conn   // persistent WS session (when cfg.Persistent)
	pvars       map[string]string // captures + generated IDs persisted across calls
	initialized bool              // once-steps have run for the current conversation
	lastRawResp []byte
}

// NewHybrid creates a Hybrid generator from configuration.
func NewHybrid(cfg registry.Config) (generators.Generator, error) {
	parsed, err := HybridConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}

	if parsed.InsecureSkipVerify {
		slog.Warn("hybrid: HTTP TLS certificate verification disabled (insecure_skip_verify=true)")
	}
	transport := &http.Transport{
		// #nosec G402 -- InsecureSkipVerify is opt-in via insecure_skip_verify; targets are operator-chosen test endpoints
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: parsed.InsecureSkipVerify},
	}
	// Proxy resolution: an explicit `proxy:` is an override; otherwise both the
	// HTTP transport and the WS leg fall back to HTTP_PROXY/HTTPS_PROXY/NO_PROXY,
	// so one external `HTTPS_PROXY=...` routes every leg through Burp with no
	// per-generator config.
	var proxyURL *url.URL
	if parsed.Proxy != "" {
		u, err := url.Parse(parsed.Proxy)
		if err != nil {
			return nil, fmt.Errorf("hybrid: invalid proxy url %q: %w", parsed.Proxy, err)
		}
		proxyURL = u
		transport.Proxy = http.ProxyURL(u)
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	h := &Hybrid{
		cfg:      parsed,
		proxyURL: proxyURL,
		client: &http.Client{
			Timeout:   parsed.RequestTimeout,
			Transport: transport,
		},
	}
	if parsed.RateLimit > 0 {
		capacity := parsed.RateLimit
		if capacity < 1.0 {
			capacity = 1.0
		}
		h.limiter = ratelimit.NewLimiter(capacity, parsed.RateLimit)
	}
	return h, nil
}

// session holds the mutable state for one run through the choreography.
type session struct {
	vars      map[string]string
	answer    string
	gotAnswer bool

	mu   sync.Mutex
	conn *websocket.Conn
}

func (s *session) getConn() *websocket.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

func (s *session) setConn(c *websocket.Conn) {
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
}

func (s *session) closeConn() {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// Generate runs the choreography n times and returns the assembled answers.
func (h *Hybrid) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}
	out := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := h.runPipeline(ctx, conv)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

// runPipeline executes the ordered steps once and returns the answer message.
func (h *Hybrid) runPipeline(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// In persistent mode every turn shares one WS connection and the persisted
	// setup captures, so pipelines must not overlap. Serialize them.
	if h.cfg.Persistent {
		h.callMu.Lock()
		defer h.callMu.Unlock()
	}

	if h.limiter != nil {
		if err := h.limiter.Wait(ctx); err != nil {
			return attempt.Message{}, fmt.Errorf("hybrid: rate limit wait cancelled: %w", err)
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.cfg.RequestTimeout)
	defer cancel()

	h.mu.Lock()
	reusing := h.cfg.Persistent && h.initialized
	sess := &session{vars: h.seedVars(conv), conn: h.conn}
	h.mu.Unlock()

	// Watcher: closing the (possibly mid-pipeline opened) connection unblocks any
	// pending WS Send/Receive when the request is cancelled or times out.
	done := make(chan struct{})
	go func() {
		select {
		case <-reqCtx.Done():
			sess.closeConn()
		case <-done:
		}
	}()
	defer close(done)

	if err := h.executeSteps(reqCtx, sess, reusing); err != nil {
		// Drop the WS session so a stale/half-open socket is not reused.
		h.mu.Lock()
		if h.conn == sess.getConn() {
			h.conn = nil
		}
		h.initialized = false
		h.mu.Unlock()
		sess.closeConn()
		return attempt.Message{}, err
	}

	if !sess.gotAnswer {
		return attempt.Message{}, fmt.Errorf("hybrid: choreography completed without producing an answer")
	}

	h.persistSession(sess)
	return attempt.NewAssistantMessage(sess.answer), nil
}

// executeSteps walks the step list, skipping once-steps (and reusing the open
// WebSocket) when a persistent session is already established.
func (h *Hybrid) executeSteps(ctx context.Context, sess *session, reusing bool) error {
	// reconnecting: persistent session that rebuilds the socket every turn
	// (reuse_connection:false). The WS setup steps must rerun even when marked
	// `once` so the fresh socket is reconnected and re-subscribed; only the HTTP
	// once-steps (whose captures persist) are skipped.
	reconnecting := reusing && !h.cfg.ReuseConnection
	for _, st := range h.cfg.Steps {
		if st.Once && reusing && (!reconnecting || !isWSStep(st.Type)) {
			continue
		}
		if st.Type == stepWSConnect && reusing && h.cfg.ReuseConnection && sess.getConn() != nil {
			continue // reuse the persistent connection
		}
		if err := h.execStep(ctx, st, sess); err != nil {
			return fmt.Errorf("step %q (%s): %w", st.Name, st.Type, err)
		}
	}
	return nil
}

// isWSStep reports whether a step operates on the WebSocket connection (as
// opposed to an HTTP request).
func isWSStep(t string) bool {
	switch t {
	case stepWSConnect, stepWSSend, stepWSAwait, stepWSStream:
		return true
	default:
		return false
	}
}

// persistSession stores connection + setup captures for reuse, or tears down the
// session when persistence is disabled.
func (h *Hybrid) persistSession(sess *session) {
	if !h.cfg.Persistent {
		sess.closeConn()
		return
	}
	// Persist the setup captures (e.g. a conversationID) so later turns reuse them.
	// When ReuseConnection is false we still close the live socket so nothing sits
	// unread between turns; the next turn reconnects + re-runs the WS setup steps.
	if !h.cfg.ReuseConnection {
		sess.closeConn()
	}
	h.mu.Lock()
	if h.cfg.ReuseConnection {
		h.conn = sess.getConn()
	} else {
		h.conn = nil
	}
	if !h.initialized {
		h.pvars = persistableVars(sess.vars)
		h.initialized = true
	}
	h.mu.Unlock()
}

// seedVars builds the per-call variable map: persisted captures + generated IDs,
// plus the current prompt as $INPUT/$INPUT_JSON and the key as $KEY. Caller holds h.mu.
func (h *Hybrid) seedVars(conv *attempt.Conversation) map[string]string {
	vars := map[string]string{}
	for k, v := range h.cfg.Vars {
		vars[k] = v
	}
	if h.cfg.APIKey != "" {
		vars["KEY"] = h.cfg.APIKey
	}
	// Generated correlation IDs: minted once per conversation, then reused so a
	// subscribe id stays stable across a persistent session.
	if h.initialized && h.cfg.Persistent {
		for k, v := range h.pvars {
			vars[k] = v
		}
	} else {
		vars["CORRELATION_ID"] = newUUID()
		vars["SUB_ID"] = newUUID()
	}
	prompt := conv.LastPrompt()
	vars["INPUT"] = prompt
	vars["INPUT_JSON"] = wsutil.JSONEscape(prompt)
	return vars
}

// persistableVars copies vars worth carrying across calls, dropping the
// per-prompt entries so the next turn re-injects a fresh prompt.
func persistableVars(vars map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range vars {
		if k == "INPUT" || k == "INPUT_JSON" {
			continue
		}
		out[k] = v
	}
	return out
}

// ClearHistory closes the persistent WebSocket session and forgets captured
// state so the next Generate starts a fresh conversation.
func (h *Hybrid) ClearHistory() {
	h.mu.Lock()
	conn := h.conn
	h.conn = nil
	h.pvars = nil
	h.initialized = false
	h.lastRawResp = nil
	h.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// LastRawResponse returns the raw bytes of the most recent answer source (the
// terminal frame, the concatenated stream, or the answer HTTP body).
func (h *Hybrid) LastRawResponse() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastRawResp
}

func (h *Hybrid) storeRaw(b []byte) {
	h.mu.Lock()
	h.lastRawResp = b
	h.mu.Unlock()
}

// Name returns the generator's fully qualified name.
func (h *Hybrid) Name() string { return "hybrid.Hybrid" }

// Description returns a human-readable description.
func (h *Hybrid) Description() string {
	return "Choreography-driven hybrid generator mixing HTTP requests and a graphql-transport-ws WebSocket (e.g. GraphQL subscription chat where the prompt is an HTTP mutation and the reply streams over WS)"
}

// render substitutes $NAME placeholders in tmpl from vars. Longer names are
// listed first so $INPUT_JSON wins over $INPUT and $ID_TOKEN over $ID. It uses a
// single left-to-right pass (strings.Replacer) that never rescans substituted
// text, so a value containing a literal "$KEY"/"$INPUT" is not re-expanded —
// this prevents payload corruption and avoids leaking $KEY when an adversarial
// prompt embeds the literal token.
func render(tmpl string, vars map[string]string) string {
	if len(vars) == 0 {
		return tmpl
	}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		pairs = append(pairs, "$"+k, vars[k])
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read never fails on supported platforms; fall back to a marker
		// rather than panicking inside a scan.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// idleDeadline returns the earlier of the context deadline and now+idle. A
// deadline always exists (now+idle at minimum), so it returns a bare time.
func idleDeadline(ctx context.Context, idle time.Duration) time.Time {
	id := time.Now().Add(idle)
	if d, ok := ctx.Deadline(); ok && d.Before(id) {
		return d
	}
	return id
}

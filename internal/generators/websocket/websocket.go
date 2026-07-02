// Package websocket provides a generic WebSocket generator for Augustus.
//
// It implements the Generator interface for targets that speak over a WebSocket
// (ws:// or wss://) rather than request/response HTTP. Each Generate call opens
// (or reuses) a connection, sends a templated text frame derived from the
// probe's prompt, then reads one or more response frames according to the
// configured read mode and returns the assembled text.
//
// The configuration vocabulary deliberately mirrors the REST generator so an
// operator can move a target between transports with minimal edits.
//
// Template placeholders substituted into the outgoing frame:
//
//	$INPUT       the prompt, verbatim (raw — frames are text by default)
//	$INPUT_JSON  the prompt, JSON-escaped (for embedding inside a JSON string)
//	$KEY         the configured api_key, verbatim
//	$MESSAGES    the full conversation as a JSON array of {role,content}
//	$VAR         any runtime hook variable, verbatim
package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	generators.Register("websocket.Websocket", NewWebsocket)
}

// Compile-time interface assertions.
var (
	_ generators.Generator      = (*Websocket)(nil)
	_ hooks.RawResponseProvider = (*Websocket)(nil)
)

// Websocket is a generic WebSocket generator.
type Websocket struct {
	types.UsageCounter // embedded but never incremented: WS endpoints report no token usage.

	cfg     Config
	wsCfg   *websocket.Config // pre-built handshake config (cloned per dial)
	limiter *ratelimit.Limiter

	// callMu serializes whole exchanges in persistent mode. The scanner shares one
	// generator instance across concurrent probe goroutines; a persistent session
	// is a single stateful WS connection, and x/net/websocket is not safe for
	// concurrent Send/Receive. Holding callMu per exchange keeps reuse sequential
	// (and makes first-call dialing race-free, so no socket is orphaned).
	callMu sync.Mutex

	mu          sync.Mutex // guards conn and lastRawResp
	conn        *websocket.Conn
	lastRawResp []byte
}

// NewWebsocket creates a WebSocket generator from configuration.
func NewWebsocket(cfg registry.Config) (generators.Generator, error) {
	parsed, err := ConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}

	wsCfg, err := wsutil.BuildHandshakeConfig(parsed.URI, parsed.Origin, parsed.Headers, parsed.Subprotocols, parsed.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	w := &Websocket{cfg: parsed, wsCfg: wsCfg}

	if parsed.RateLimit > 0 {
		capacity := parsed.RateLimit
		if capacity < 1.0 {
			capacity = 1.0 // always allow at least one request
		}
		w.limiter = ratelimit.NewLimiter(capacity, parsed.RateLimit)
	}

	return w, nil
}

// Generate sends the conversation's last prompt to the WebSocket target and
// returns n responses. As with REST, n completions are produced by repeating the
// request; WebSocket targets do not natively return multiple completions.
func (w *Websocket) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := w.callOnce(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}
	return responses, nil
}

// callOnce performs one send/receive exchange against the target.
//
// In persistent mode a reused connection may have been idle-closed by the
// server since the previous call; that surfaces as a send/receive error rather
// than a response. When the request context is still live (so the failure is the
// socket, not a cancellation or a genuine target error mid-stream), callOnce
// redials once and retries. The retry is bounded to reused connections, so a
// real request failure on a freshly dialed socket is reported, never masked.
func (w *Websocket) callOnce(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	// In persistent mode every call shares one WS connection, so exchanges must
	// not overlap (x/net/websocket forbids concurrent Send/Receive).
	if w.cfg.Persistent {
		w.callMu.Lock()
		defer w.callMu.Unlock()
	}

	if w.limiter != nil {
		if err := w.limiter.Wait(ctx); err != nil {
			return attempt.Message{}, fmt.Errorf("websocket: rate limit wait cancelled: %w", err)
		}
	}

	reqCtx, cancel := context.WithTimeout(ctx, w.cfg.RequestTimeout)
	defer cancel()

	conn, reused, err := w.acquireConn(reqCtx)
	if err != nil {
		return attempt.Message{}, err
	}

	msg, err := w.runExchange(reqCtx, conn, conv)
	if err == nil {
		if !w.cfg.Persistent {
			w.dropConn(conn)
		}
		return msg, nil
	}

	// A failed exchange invalidates the connection; drop it so we never reuse a
	// half-closed socket.
	w.dropConn(conn)
	if !reused || reqCtx.Err() != nil {
		return attempt.Message{}, err
	}

	// Stale persistent socket: redial once (acquireConn dials fresh because we
	// just dropped the stored connection) and retry the exchange.
	conn, _, err = w.acquireConn(reqCtx)
	if err != nil {
		return attempt.Message{}, err
	}
	msg, err = w.runExchange(reqCtx, conn, conv)
	if err != nil {
		w.dropConn(conn)
		return attempt.Message{}, err
	}
	if !w.cfg.Persistent {
		w.dropConn(conn)
	}
	return msg, nil
}

// runExchange installs a context watcher around a single send/receive exchange.
// Closing the connection unblocks any pending Send/Receive when the request
// context is cancelled or times out; the done channel disarms the watcher on the
// happy path so a healthy persistent connection is never closed.
func (w *Websocket) runExchange(reqCtx context.Context, conn *websocket.Conn, conv *attempt.Conversation) (attempt.Message, error) {
	conn.MaxPayloadBytes = wsutil.MaxFrameBytes

	done := make(chan struct{})
	go func() {
		select {
		case <-reqCtx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	return w.exchange(reqCtx, conn, conv)
}

// acquireConn returns a usable connection, reusing the persistent one when
// configured and present, otherwise dialing a fresh one. The bool reports
// whether an existing connection was reused.
func (w *Websocket) acquireConn(ctx context.Context) (*websocket.Conn, bool, error) {
	if w.cfg.Persistent {
		w.mu.Lock()
		conn := w.conn
		w.mu.Unlock()
		if conn != nil {
			return conn, true, nil
		}
	}

	cfgCopy := *w.wsCfg
	cfgCopy.Header = w.wsCfg.Header.Clone()
	conn, err := cfgCopy.DialContext(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("websocket: dial %s failed: %w", w.cfg.URI, err)
	}

	if w.cfg.Persistent {
		w.mu.Lock()
		w.conn = conn
		w.mu.Unlock()
	}
	return conn, false, nil
}

// dropConn closes conn and, if it is the stored persistent connection, clears it.
func (w *Websocket) dropConn(conn *websocket.Conn) {
	w.mu.Lock()
	if w.conn == conn {
		w.conn = nil
	}
	w.mu.Unlock()
	_ = conn.Close()
}

// exchange sends the templated prompt and reads the response per the read mode.
func (w *Websocket) exchange(ctx context.Context, conn *websocket.Conn, conv *attempt.Conversation) (attempt.Message, error) {
	prompt := conv.LastPrompt()
	hookVars := types.HookVarsFromContext(ctx)
	payload := w.buildPayload(conv, prompt, hookVars)

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := websocket.Message.Send(conn, payload); err != nil {
		return attempt.Message{}, fmt.Errorf("websocket: send failed: %w", err)
	}

	content, err := w.readResponse(ctx, conn)
	if err != nil {
		return attempt.Message{}, err
	}
	return attempt.NewAssistantMessage(content), nil
}

// readResponse consumes frames according to the configured read mode and returns
// the assembled text.
func (w *Websocket) readResponse(ctx context.Context, conn *websocket.Conn) (string, error) {
	if w.cfg.ReadMode == ReadModeSingle {
		frame, err := w.readFrame(ctx, conn, false)
		if err != nil {
			return "", err
		}
		w.storeRaw(frame)
		return w.frameText(frame), nil
	}
	return w.readMultiple(ctx, conn)
}

// readMultiple accumulates frames for until_close / until_marker modes. Idle and
// connection-close conditions terminate reading gracefully; only a cancelled or
// timed-out request context produces an error, because a partial stream after a
// real timeout should not be mistaken for a complete answer.
func (w *Websocket) readMultiple(ctx context.Context, conn *websocket.Conn) (string, error) {
	var (
		parts    []string
		rawParts [][]byte
	)
	for {
		frame, err := w.readFrame(ctx, conn, true)
		if err != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("websocket: read cancelled: %w", ctx.Err())
			}
			if errors.Is(err, io.EOF) || wsutil.IsTimeout(err) {
				break // server closed, or idle gap reached: stream complete
			}
			return "", err
		}

		if w.cfg.ReadMode == ReadModeUntilMarker && w.isTerminator(frame) {
			break // terminator frame is a sentinel, not content
		}

		rawParts = append(rawParts, frame)
		if text := w.frameText(frame); text != "" {
			parts = append(parts, text)
		}
	}

	w.storeRaw(wsutil.JoinRaw(rawParts))
	return strings.Join(parts, ""), nil
}

// readFrame reads a single frame into memory. In multi-frame mode the per-frame
// idle timeout bounds how long it waits before concluding the stream is done.
func (w *Websocket) readFrame(ctx context.Context, conn *websocket.Conn, perFrameIdle bool) ([]byte, error) {
	deadline, hasDeadline := ctx.Deadline()
	if perFrameIdle {
		idle := time.Now().Add(w.cfg.IdleTimeout)
		if !hasDeadline || idle.Before(deadline) {
			deadline, hasDeadline = idle, true
		}
	}
	if hasDeadline {
		_ = conn.SetReadDeadline(deadline)
	}

	var data []byte
	if err := websocket.Message.Receive(conn, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// isTerminator reports whether frame signals the end of an until_marker stream.
func (w *Websocket) isTerminator(frame []byte) bool {
	if w.cfg.DoneMarker != "" && strings.Contains(string(frame), w.cfg.DoneMarker) {
		return true
	}
	if w.cfg.DoneField != "" {
		if val, err := wsutil.ExtractField(frame, w.cfg.DoneField); err == nil && val == w.cfg.DoneValue {
			return true
		}
	}
	return false
}

// frameText extracts the text content of a frame, applying JSON field extraction
// when configured. On extraction failure it falls back to the raw frame so a
// schema mismatch never silently discards a response.
func (w *Websocket) frameText(frame []byte) string {
	if !w.cfg.ResponseJSON {
		return string(frame)
	}
	val, err := wsutil.ExtractField(frame, w.cfg.ResponseJSONField)
	if err != nil {
		return string(frame)
	}
	return val
}

// buildPayload renders the outgoing frame from the request template in a single
// left-to-right pass (strings.Replacer). A single pass never rescans substituted
// text, so a prompt that contains a literal placeholder (e.g. "$MESSAGES" or
// "$KEY") is not re-expanded — preventing payload corruption and api_key leaks.
// Longer placeholders are listed first so $INPUT_JSON wins over $INPUT.
func (w *Websocket) buildPayload(conv *attempt.Conversation, prompt string, hookVars map[string]string) string {
	keys := make([]string, 0, len(hookVars))
	for k := range hookVars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	pairs := make([]string, 0, (len(keys)+4)*2)
	for _, k := range keys {
		pairs = append(pairs, "$"+k, hookVars[k])
	}
	pairs = append(
		pairs,
		"$INPUT_JSON", wsutil.JSONEscape(prompt),
		"$MESSAGES", conversationToJSON(conv),
		"$INPUT", prompt,
	)
	// Only substitute $KEY when an api_key is configured; otherwise leave the
	// literal token untouched (matches prior behavior).
	if w.cfg.APIKey != "" {
		pairs = append(pairs, "$KEY", w.cfg.APIKey)
	}
	return strings.NewReplacer(pairs...).Replace(w.cfg.ReqTemplate)
}

func (w *Websocket) storeRaw(b []byte) {
	w.mu.Lock()
	w.lastRawResp = b
	w.mu.Unlock()
}

// LastRawResponse returns the raw bytes of the most recent response (the single
// frame, or the concatenation of accumulated frames). Implements
// hooks.RawResponseProvider.
func (w *Websocket) LastRawResponse() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastRawResp
}

// ClearHistory closes any persistent connection so the next Generate starts a
// fresh session. Stateless (non-persistent) generators have nothing to reset.
func (w *Websocket) ClearHistory() {
	w.mu.Lock()
	conn := w.conn
	w.conn = nil
	w.lastRawResp = nil
	w.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// Name returns the generator's fully qualified name.
func (w *Websocket) Name() string { return "websocket.Websocket" }

// Description returns a human-readable description.
func (w *Websocket) Description() string {
	return "Generic WebSocket generator for ws:// and wss:// endpoints with single, until-close, and until-marker read modes"
}

// conversationToJSON serializes a Conversation as a JSON array of {role,content}
// objects for the $MESSAGES template variable.
func conversationToJSON(conv *attempt.Conversation) string {
	msgs := conv.ToMessages()
	type jsonMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	out := make([]jsonMsg, len(msgs))
	for i, m := range msgs {
		out[i] = jsonMsg{Role: string(m.Role), Content: m.Content}
	}
	data, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(data)
}

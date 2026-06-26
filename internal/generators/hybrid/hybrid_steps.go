package hybrid

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/praetorian-inc/augustus/internal/generators/wsutil"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// maxHTTPBody caps an HTTP response body read, mirroring the WS frame cap.
const maxHTTPBody = 10 * 1024 * 1024

// execStep dispatches one step to its handler.
func (h *Hybrid) execStep(ctx context.Context, st step, sess *session) error {
	switch st.Type {
	case stepHTTP:
		return h.execHTTP(ctx, st, sess)
	case stepHTTPPoll:
		return h.execHTTPPoll(ctx, st, sess)
	case stepWSConnect:
		return h.execWSConnect(ctx, st, sess)
	case stepWSSend:
		return h.execWSSend(ctx, st, sess)
	case stepWSAwait:
		return h.execWSAwait(ctx, st, sess)
	case stepWSStream:
		return h.execWSStream(ctx, st, sess)
	default:
		return fmt.Errorf("unknown step type %q", st.Type)
	}
}

// execHTTP tries each request form until one yields a 2xx response with all
// captures resolved (fallback across alternative schemas). The last error is
// returned if every form fails.
func (h *Hybrid) execHTTP(ctx context.Context, st step, sess *session) error {
	hookVars := types.HookVarsFromContext(ctx)
	var lastErr error
	for i, form := range st.Forms {
		body, captured, err := h.tryHTTPForm(ctx, form, sess, hookVars)
		if err != nil {
			lastErr = fmt.Errorf("form %d: %w", i, err)
			continue
		}
		for k, v := range captured {
			sess.vars[k] = v
		}
		if st.Answer {
			text, ok := wsutil.ExtractFirst(body, st.ResponseFields)
			if !ok {
				lastErr = fmt.Errorf("form %d: none of response_field %v resolved in answer body", i, st.ResponseFields)
				continue
			}
			sess.answer = text
			sess.gotAnswer = true
			h.storeRaw(body)
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no request forms configured")
	}
	return lastErr
}

// tryHTTPForm performs one HTTP form and returns the response body and captures.
func (h *Hybrid) tryHTTPForm(ctx context.Context, form httpForm, sess *session, hookVars map[string]string) ([]byte, map[string]string, error) {
	url := render(form.URL, sess.vars)
	reqBody := h.renderWithHooks(form.Body, sess.vars, hookVars)

	req, err := http.NewRequestWithContext(ctx, form.Method, url, strings.NewReader(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range form.Headers {
		req.Header.Set(k, h.renderWithHooks(v, sess.vars, hookVars))
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	captured := map[string]string{}
	for varName, path := range form.Capture {
		val, err := wsutil.ExtractField(body, path)
		if err != nil {
			return nil, nil, fmt.Errorf("capture %q via %q: %w", varName, path, err)
		}
		captured[varName] = val
	}
	return body, captured, nil
}

// execHTTPPoll re-requests an endpoint until a readiness condition holds, then
// (when answer:true) extracts the reply. Readiness is either a status field
// flipping to a value (until_field == until_value) or, absent that, the answer
// field appearing (response_field resolves non-empty). Captures are applied only
// from the ready response. It gives up after MaxAttempts or when the request
// context is cancelled/times out — a partial poll never masquerades as an answer.
func (h *Hybrid) execHTTPPoll(ctx context.Context, st step, sess *session) error {
	hookVars := types.HookVarsFromContext(ctx)

	for attempt := 1; attempt <= st.MaxAttempts; attempt++ {
		body, captured, err := h.tryPollForms(ctx, st, sess, hookVars)
		if err != nil {
			return fmt.Errorf("poll attempt %d/%d: %w", attempt, st.MaxAttempts, err)
		}

		if h.pollReady(st, body) {
			for k, v := range captured {
				sess.vars[k] = v
			}
			if st.Answer {
				text, ok := wsutil.ExtractFirst(body, st.ResponseFields)
				if !ok {
					return fmt.Errorf("poll ready but none of response_field %v resolved", st.ResponseFields)
				}
				sess.answer = text
				sess.gotAnswer = true
				h.storeRaw(body)
			}
			return nil
		}

		if attempt == st.MaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("poll cancelled: %w", ctx.Err())
		case <-time.After(st.Interval):
		}
	}
	return fmt.Errorf("poll exhausted after %d attempts without reaching the readiness condition", st.MaxAttempts)
}

// tryPollForms runs one polling round, trying each configured form until one
// succeeds (fallback across alternative schemas, matching execHTTP). The last
// error is returned if every form fails.
func (h *Hybrid) tryPollForms(ctx context.Context, st step, sess *session, hookVars map[string]string) ([]byte, map[string]string, error) {
	var lastErr error
	for i, form := range st.Forms {
		body, captured, err := h.tryHTTPForm(ctx, form, sess, hookVars)
		if err != nil {
			lastErr = fmt.Errorf("form %d: %w", i, err)
			continue
		}
		return body, captured, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no request forms configured")
	}
	return nil, nil, lastErr
}

// pollReady reports whether a poll response satisfies the readiness condition.
// When until_field is configured it is authoritative; otherwise readiness is the
// presence of a non-empty response_field value.
func (h *Hybrid) pollReady(st step, body []byte) bool {
	if st.UntilField != "" {
		val, err := wsutil.ExtractField(body, st.UntilField)
		return err == nil && val == st.UntilValue
	}
	_, ok := wsutil.ExtractFirst(body, st.ResponseFields)
	return ok
}

// execWSConnect dials the WebSocket and stores it on the session.
func (h *Hybrid) execWSConnect(ctx context.Context, st step, sess *session) error {
	url := render(st.WSURL, sess.vars)
	origin := render(st.Origin, sess.vars)
	headers := renderMap(st.Headers, sess.vars)

	wsCfg, err := wsutil.BuildHandshakeConfig(url, origin, headers, []string{st.Subprotocol}, st.InsecureSkipVerify)
	if err != nil {
		return err
	}
	proxyURL, err := wsutil.EnvProxyFor(url, h.proxyURL)
	if err != nil {
		return fmt.Errorf("resolve proxy for %s: %w", url, err)
	}
	var conn *websocket.Conn
	if proxyURL != nil {
		conn, err = wsutil.DialViaProxy(ctx, wsCfg, proxyURL)
	} else {
		conn, err = wsCfg.DialContext(ctx)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", url, err)
	}
	conn.MaxPayloadBytes = wsutil.MaxFrameBytes
	sess.setConn(conn)
	return nil
}

// execWSSend renders and sends one frame.
func (h *Hybrid) execWSSend(ctx context.Context, st step, sess *session) error {
	conn := sess.getConn()
	if conn == nil {
		return errors.New("no open websocket")
	}
	hookVars := types.HookVarsFromContext(ctx)
	frame := h.renderWithHooks(st.Frame, sess.vars, hookVars)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := websocket.Message.Send(conn, frame); err != nil {
		return fmt.Errorf("send frame: %w", err)
	}
	return nil
}

// execWSAwait reads frames until one matches the configured field/value
// (answering protocol pings along the way).
func (h *Hybrid) execWSAwait(ctx context.Context, st step, sess *session) error {
	conn := sess.getConn()
	if conn == nil {
		return errors.New("no open websocket")
	}
	for {
		frame, err := h.readFrame(ctx, conn)
		if err != nil {
			return fmt.Errorf("await %s==%s: %w", st.MatchField, st.MatchValue, err)
		}
		if h.handlePing(conn, frame) {
			continue
		}
		if val, err := wsutil.ExtractField(frame, st.MatchField); err == nil && val == st.MatchValue {
			return nil
		}
	}
}

// execWSStream reads frames, assembles the answer, and stops on the completion
// signal (a matching field value or a graphql-ws `complete`/`error` frame).
func (h *Hybrid) execWSStream(ctx context.Context, st step, sess *session) error {
	conn := sess.getConn()
	if conn == nil {
		return errors.New("no open websocket")
	}

	var parts []string
	var lastNonEmpty string
	var rawFrames [][]byte

	finish := func(final []byte) {
		if st.Assembly == AssemblyConcat {
			sess.answer = strings.Join(parts, "")
			h.storeRaw(wsutil.JoinRaw(rawFrames))
		} else {
			sess.answer = lastNonEmpty
			if final != nil {
				h.storeRaw(final)
			} else {
				h.storeRaw(wsutil.JoinRaw(rawFrames))
			}
		}
		sess.gotAnswer = true
	}

	for {
		frame, err := h.readFrame(ctx, conn)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("stream read cancelled: %w", ctx.Err())
			}
			if errors.Is(err, io.EOF) || wsutil.IsTimeout(err) {
				if st.Assembly == AssemblyConcat {
					finish(nil) // server closed / idle gap ends a delta stream
					return nil
				}
				return fmt.Errorf("stream ended before completion signal")
			}
			return err
		}
		if h.handlePing(conn, frame) {
			continue
		}
		if frameType, _ := wsutil.ExtractField(frame, "$.type"); frameType == "error" {
			return fmt.Errorf("server sent error frame: %s", truncate(string(frame), 300))
		} else if frameType == "complete" {
			// A graphql-transport-ws `complete` frame carries no payload. For
			// assembly:final the answer is the terminal frame identified by
			// complete_field==complete_value; if the stream completes before that
			// frame arrives, returning lastNonEmpty would emit a partial delta —
			// fail instead.
			if st.Assembly == AssemblyFinal {
				return fmt.Errorf("stream completed before terminal frame (%s==%q)", st.CompleteField, st.CompleteValue)
			}
			finish(nil)
			return nil
		}

		rawFrames = append(rawFrames, frame)
		if text, ok := wsutil.ExtractFirst(frame, st.ResponseFields); ok {
			parts = append(parts, text)
			lastNonEmpty = text
		}

		if st.CompleteField != "" {
			if val, err := wsutil.ExtractField(frame, st.CompleteField); err == nil && val == st.CompleteValue {
				if text, ok := wsutil.ExtractFirst(frame, st.ResponseFields); ok {
					lastNonEmpty = text
				}
				finish(frame)
				return nil
			}
		}
	}
}

// handlePing answers a graphql-transport-ws protocol ping with a pong. It
// returns true when the frame was a ping (and thus not response data).
func (h *Hybrid) handlePing(conn *websocket.Conn, frame []byte) bool {
	if t, _ := wsutil.ExtractField(frame, "$.type"); t == "ping" {
		_ = websocket.Message.Send(conn, `{"type":"pong"}`)
		return true
	}
	return false
}

// readFrame reads one frame, bounding the wait by the per-frame idle timeout (or
// the request deadline, whichever is sooner).
func (h *Hybrid) readFrame(ctx context.Context, conn *websocket.Conn) ([]byte, error) {
	if deadline, ok := idleDeadline(ctx, h.cfg.IdleTimeout); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	var data []byte
	if err := websocket.Message.Receive(conn, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// renderWithHooks substitutes template vars and runtime hook vars in a single
// pass. Hook values are JSON-escaped because hybrid bodies are typically JSON.
// Merging both maps before a single render() avoids a second pass re-expanding a
// placeholder that happens to appear inside an already-substituted value (e.g. a
// prompt that contains the literal "$SOME_HOOK").
func (h *Hybrid) renderWithHooks(tmpl string, vars, hookVars map[string]string) string {
	if len(hookVars) == 0 {
		return render(tmpl, vars)
	}
	merged := make(map[string]string, len(vars)+len(hookVars))
	for k, v := range vars {
		merged[k] = v
	}
	// Hook vars win over static vars on a name collision (preserving the previous
	// hooks-after-vars precedence).
	for k, v := range hookVars {
		merged[k] = wsutil.JSONEscape(v)
	}
	return render(tmpl, merged)
}

// renderMap renders every value of a string map.
func renderMap(in map[string]string, vars map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = render(v, vars)
	}
	return out
}

// truncate shortens s for safe inclusion in error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

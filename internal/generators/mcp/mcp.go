// Package mcp provides a Model Context Protocol (MCP) generator for Augustus.
//
// It implements the Generator interface for targets that speak MCP, letting
// probes treat an MCP server as the thing under test. Two transports are
// supported behind a single config vocabulary:
//
//	transport: http    Streamable HTTP (JSON-RPC over HTTP POST + SSE) to a remote server
//	transport: sse     legacy HTTP+SSE (GET /sse stream + POST /messages), as older FastMCP servers expose
//	transport: stdio   a locally launched subprocess speaking JSON-RPC over stdin/stdout
//
// and two modes select what a Generate call does once connected:
//
//	mode: tool_call    call a configured tool, injecting the prompt into an argument,
//	                   and return the tool result text (prompt-injection / BOLA /
//	                   tool-coercion / SSRF surface)
//	mode: list_tools   ignore the prompt and return the server's advertised tool
//	                   names/descriptions/schemas (tool-poisoning / rug-pull surface)
//
// Template placeholders substituted into tool arguments (arguments_template, or
// string values of the static `arguments` map):
//
//	$INPUT       the prompt, verbatim
//	$INPUT_JSON  the prompt, JSON-escaped (for embedding inside a JSON string)
//	$KEY         the configured api_key, verbatim
//	$VAR         any runtime hook variable, verbatim
//
// The protocol layer is the official MCP Go SDK, which owns the initialize
// handshake, capability negotiation, and both transports.
package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/hooks"
	"github.com/praetorian-inc/augustus/pkg/ratelimit"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	generators.Register("mcp.MCP", NewMCP)
}

// Compile-time interface assertions.
var (
	_ generators.Generator      = (*MCP)(nil)
	_ hooks.RawResponseProvider = (*MCP)(nil)
	_ types.ToolInvoker         = (*MCP)(nil)
)

// MCP is a Model Context Protocol generator.
type MCP struct {
	types.UsageCounter // embedded but never incremented: MCP tool results report no token usage.

	cfg     Config
	limiter *ratelimit.Limiter

	// mu guards the persistent session pointer. Establishing the session is done
	// under the lock so concurrent first callers cannot open duplicate sessions;
	// once connected, individual tool calls run concurrently because the SDK's
	// ClientSession multiplexes JSON-RPC requests by id.
	mu         sync.Mutex
	sess       *mcpsdk.ClientSession
	sessCancel context.CancelFunc // cancels the context that owns sess's transport stream

	rawMu       sync.Mutex
	lastRawResp []byte

	// toolsCache memoizes ListTools: the advertised tool set is stable per
	// session, so N probes cost one real tools/list. Cleared whenever the
	// session is dropped or reset.
	toolsMu    sync.Mutex
	toolsCache []map[string]any
}

// NewMCP creates an MCP generator from configuration.
func NewMCP(cfg registry.Config) (generators.Generator, error) {
	parsed, err := ConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}

	m := &MCP{cfg: parsed}

	if parsed.RateLimit > 0 {
		capacity := parsed.RateLimit
		if capacity < 1.0 {
			capacity = 1.0 // always allow at least one request
		}
		m.limiter = ratelimit.NewLimiter(capacity, parsed.RateLimit)
	}

	return m, nil
}

// Generate sends the conversation's last prompt to the MCP target and returns n
// responses. As with REST/WebSocket, n completions are produced by repeating the
// request; MCP targets do not natively return multiple completions.
func (m *MCP) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := m.generateOnce(ctx, conv)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}
	return responses, nil
}

// generateOnce performs one MCP exchange over a managed session.
func (m *MCP) generateOnce(ctx context.Context, conv *attempt.Conversation) (attempt.Message, error) {
	var msg attempt.Message
	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		var e error
		msg, e = m.exchange(ctx, sess, conv)
		return e
	})
	if err != nil {
		return attempt.Message{}, err
	}
	return msg, nil
}

// withSession runs fn against an acquired session, applying the rate limit and
// reconnecting once if a reused persistent session turns out to have been closed
// by the server. It is the single place session lifecycle + retry live, shared
// by Generate, ListTools, and CallTool.
func (m *MCP) withSession(ctx context.Context, fn func(context.Context, *mcpsdk.ClientSession) error) error {
	if m.limiter != nil {
		if err := m.limiter.Wait(ctx); err != nil {
			return fmt.Errorf("mcp: rate limit wait cancelled: %w", err)
		}
	}

	sess, reused, release, err := m.acquireSession(ctx)
	if err != nil {
		return err
	}
	err = fn(ctx, sess)
	release()
	if err == nil {
		return nil
	}

	// A reused persistent session may have been closed by the server (HTTP idle
	// timeout, stdio subprocess exit) since the previous call. Reconnect once and
	// retry, but only when the failure was not a cancellation/timeout of our own
	// request — otherwise a genuine target error on a fresh socket would be masked.
	if reused && ctx.Err() == nil {
		m.dropSession()
		sess, _, release, err = m.acquireSession(ctx)
		if err != nil {
			return err
		}
		defer release()
		return fn(ctx, sess)
	}
	return err
}

// acquireSession returns a session, reusing the persistent one when present and
// dialing a fresh one otherwise. The bool reports whether an existing session
// was reused; release closes the session for non-persistent generators and is a
// no-op for persistent ones.
func (m *MCP) acquireSession(ctx context.Context) (*mcpsdk.ClientSession, bool, func(), error) {
	if !m.cfg.Persistent {
		sess, cancel, err := m.connect(ctx)
		if err != nil {
			return nil, false, nil, err
		}
		return sess, false, func() { _ = sess.Close(); cancel() }, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		return m.sess, true, func() {}, nil
	}
	sess, cancel, err := m.connect(ctx)
	if err != nil {
		return nil, false, nil, err
	}
	m.sess = sess
	m.sessCancel = cancel
	return sess, false, func() {}, nil
}

// connect establishes and initializes a new MCP session. It returns a cancel
// func that tears down the session's transport stream; the caller must invoke it
// when the session is dropped.
//
// The context passed to the SDK's Connect owns the transport's persistent stream
// for the whole session lifetime, not just the handshake — notably the legacy
// SSE transport's GET /sse stream is bound to it, and cancelling it mid-session
// closes the stream so subsequent tools/* calls fail. So the session context is
// derived from context.Background(), NOT the per-Generate caller context (which
// ends when this call returns). A handshake timeout is enforced separately and
// only cancels on failure or caller cancellation, never after a successful
// connect.
func (m *MCP) connect(ctx context.Context) (*mcpsdk.ClientSession, context.CancelFunc, error) {
	transport, err := m.buildTransport()
	if err != nil {
		return nil, nil, err
	}

	client := mcpsdk.NewClient(&mcpsdk.Implementation{
		Name:    m.cfg.ClientName,
		Version: m.cfg.ClientVersion,
	}, nil)

	sessCtx, sessCancel := context.WithCancel(context.Background())

	type result struct {
		sess *mcpsdk.ClientSession
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		s, e := client.Connect(sessCtx, transport, nil)
		ch <- result{s, e}
	}()

	timer := time.NewTimer(m.cfg.RequestTimeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		if r.err != nil {
			sessCancel()
			return nil, nil, fmt.Errorf("mcp: connect to %s failed: %w", m.target(), r.err)
		}
		return r.sess, sessCancel, nil
	case <-timer.C:
		sessCancel()
		<-ch // let the aborted Connect goroutine finish before returning
		return nil, nil, fmt.Errorf("mcp: connect to %s timed out after %s", m.target(), m.cfg.RequestTimeout)
	case <-ctx.Done():
		sessCancel()
		<-ch
		return nil, nil, fmt.Errorf("mcp: connect to %s cancelled: %w", m.target(), ctx.Err())
	}
}

// buildTransport constructs a fresh transport for one connection. A CommandTransport
// wraps a single-use exec.Cmd, so it must be rebuilt per connect.
func (m *MCP) buildTransport() (mcpsdk.Transport, error) {
	switch m.cfg.Transport {
	case TransportStdio:
		cmd := exec.Command(m.cfg.Command, m.cfg.Args...)
		if len(m.cfg.Env) > 0 {
			cmd.Env = os.Environ()
			for k, v := range m.cfg.Env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
		return &mcpsdk.CommandTransport{Command: cmd}, nil
	case TransportHTTP:
		return &mcpsdk.StreamableClientTransport{
			Endpoint:             m.cfg.Endpoint,
			HTTPClient:           m.httpClient(),
			DisableStandaloneSSE: m.cfg.DisableStandaloneSSE,
		}, nil
	case TransportSSE:
		return &mcpsdk.SSEClientTransport{
			Endpoint:   m.cfg.Endpoint,
			HTTPClient: m.httpClient(),
		}, nil
	default:
		return nil, fmt.Errorf("mcp: unsupported transport %q", m.cfg.Transport)
	}
}

// httpClient builds the HTTP client for the streamable transport, injecting
// configured headers (with $KEY substituted from api_key) on every request and
// honoring insecure_skip_verify. The cloned transport keeps Go's default
// ProxyFromEnvironment (HTTPS_PROXY/HTTP_PROXY); an explicit `proxy` config key
// overrides that for the common Burp-interception workflow.
func (m *MCP) httpClient() *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if m.cfg.ProxyURL != nil {
		base.Proxy = http.ProxyURL(m.cfg.ProxyURL)
	}
	if m.cfg.InsecureSkipVerify {
		base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator-opt-in for scanning self-signed targets
		slog.Warn("mcp: TLS certificate verification disabled (insecure_skip_verify=true)", "endpoint", m.cfg.Endpoint)
	}

	headers := make(map[string]string, len(m.cfg.Headers))
	for k, v := range m.cfg.Headers {
		if m.cfg.APIKey != "" {
			v = strings.ReplaceAll(v, "$KEY", m.cfg.APIKey)
		}
		headers[k] = v
	}
	if len(headers) == 0 {
		return &http.Client{Transport: base}
	}
	return &http.Client{Transport: &headerTransport{base: base, headers: headers}}
}

// exchange dispatches one request according to the configured mode.
func (m *MCP) exchange(ctx context.Context, sess *mcpsdk.ClientSession, conv *attempt.Conversation) (attempt.Message, error) {
	callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
	defer cancel()

	if m.cfg.Mode == ModeListTools {
		return m.listTools(callCtx, sess)
	}
	return m.callTool(callCtx, sess, conv)
}

// callTool issues tools/call for the configured tool and returns the assembled
// text of the result. A tool-level error (IsError) is not a Go error: the error
// text is a valid observation for a detector (e.g. "access denied" vs a data
// leak), so it is returned as the response. Only transport/protocol failures
// return an error.
func (m *MCP) callTool(ctx context.Context, sess *mcpsdk.ClientSession, conv *attempt.Conversation) (attempt.Message, error) {
	if m.cfg.ToolName == "" {
		return attempt.Message{}, fmt.Errorf("mcp: %q mode requires 'tool_name' in generator config", ModeToolCall)
	}
	if m.cfg.ArgName == "" && m.cfg.ArgumentsTemplate == "" {
		return attempt.Message{}, fmt.Errorf("mcp: %q mode requires 'arg_name' or 'arguments_template' in generator config", ModeToolCall)
	}

	args, err := m.buildArguments(ctx, conv.LastPrompt())
	if err != nil {
		return attempt.Message{}, err
	}

	result, err := sess.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      m.cfg.ToolName,
		Arguments: args,
	})
	if err != nil {
		return attempt.Message{}, fmt.Errorf("mcp: tools/call %q failed: %w", m.cfg.ToolName, err)
	}

	m.storeRawJSON(result)
	return attempt.NewAssistantMessage(contentText(result.Content)), nil
}

// listTools issues tools/list and returns the advertised tools rendered as text
// so detectors can inspect names, descriptions, and schemas for injected content.
func (m *MCP) listTools(ctx context.Context, sess *mcpsdk.ClientSession) (attempt.Message, error) {
	result, err := sess.ListTools(ctx, nil)
	if err != nil {
		return attempt.Message{}, fmt.Errorf("mcp: tools/list failed: %w", err)
	}

	m.storeRawJSON(result)
	return attempt.NewAssistantMessage(formatTools(result.Tools)), nil
}

// ListTools implements types.ToolInvoker. It returns the target's advertised
// tools in the canonical Conversation.Tools wire shape, memoizing the result
// because the advertised set is stable per session (N probes → one tools/list).
func (m *MCP) ListTools(ctx context.Context) ([]map[string]any, error) {
	m.toolsMu.Lock()
	cached := m.toolsCache
	m.toolsMu.Unlock()
	if cached != nil {
		return cached, nil
	}

	var tools []map[string]any
	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
		defer cancel()
		result, err := sess.ListTools(callCtx, nil)
		if err != nil {
			return fmt.Errorf("mcp: tools/list failed: %w", err)
		}
		m.storeRawJSON(result)
		tools = toolsToMaps(result.Tools)
		return nil
	})
	if err != nil {
		return nil, err
	}

	m.toolsMu.Lock()
	m.toolsCache = tools
	m.toolsMu.Unlock()
	return tools, nil
}

// CallTool implements types.ToolInvoker: it invokes the named tool directly and
// returns its result. A tool-level error surfaces via ToolResult.IsError (a
// valid security observation); only transport/protocol failures return an error.
func (m *MCP) CallTool(ctx context.Context, name string, args map[string]any) (types.ToolResult, error) {
	var out types.ToolResult
	err := m.withSession(ctx, func(ctx context.Context, sess *mcpsdk.ClientSession) error {
		callCtx, cancel := context.WithTimeout(ctx, m.cfg.RequestTimeout)
		defer cancel()
		result, err := sess.CallTool(callCtx, &mcpsdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			return fmt.Errorf("mcp: tools/call %q failed: %w", name, err)
		}
		raw, _ := json.Marshal(result)
		m.rawMu.Lock()
		m.lastRawResp = raw
		m.rawMu.Unlock()
		out = types.ToolResult{Text: contentText(result.Content), Raw: raw, IsError: result.IsError}
		return nil
	})
	if err != nil {
		return types.ToolResult{}, err
	}
	return out, nil
}

// toolsToMaps converts SDK tool descriptors into the canonical Conversation.Tools
// wire shape (name/description/parameters).
func toolsToMaps(tools []*mcpsdk.Tool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		tm := map[string]any{"name": t.Name}
		if t.Description != "" {
			tm["description"] = t.Description
		}
		if t.InputSchema != nil {
			tm["parameters"] = t.InputSchema
		}
		out = append(out, tm)
	}
	return out
}

// buildArguments renders the tool arguments for one call. When arguments_template
// is set it is rendered and parsed as a JSON object; otherwise the static
// arguments map is copied (with $-substitution applied to string values) and the
// prompt is placed under arg_name.
func (m *MCP) buildArguments(ctx context.Context, prompt string) (map[string]any, error) {
	hookVars := types.HookVarsFromContext(ctx)

	if m.cfg.ArgumentsTemplate != "" {
		rendered := substitute(m.cfg.ArgumentsTemplate, prompt, m.cfg.APIKey, hookVars)
		var args map[string]any
		if err := json.Unmarshal([]byte(rendered), &args); err != nil {
			return nil, fmt.Errorf("mcp: arguments_template did not render to a JSON object: %w", err)
		}
		return args, nil
	}

	args := make(map[string]any, len(m.cfg.Arguments)+1)
	for k, v := range m.cfg.Arguments {
		if s, ok := v.(string); ok {
			args[k] = substitute(s, prompt, m.cfg.APIKey, hookVars)
		} else {
			args[k] = v
		}
	}
	args[m.cfg.ArgName] = prompt
	return args, nil
}

// dropSession closes and clears the stored persistent session, then cancels the
// context that owns its transport stream.
func (m *MCP) dropSession() {
	m.mu.Lock()
	sess := m.sess
	cancel := m.sessCancel
	m.sess = nil
	m.sessCancel = nil
	m.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
	if cancel != nil {
		cancel()
	}
	m.toolsMu.Lock()
	m.toolsCache = nil
	m.toolsMu.Unlock()
}

func (m *MCP) storeRawJSON(v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	m.rawMu.Lock()
	m.lastRawResp = data
	m.rawMu.Unlock()
}

// LastRawResponse returns the raw JSON of the most recent tool result or tool
// list. Implements hooks.RawResponseProvider.
func (m *MCP) LastRawResponse() []byte {
	m.rawMu.Lock()
	defer m.rawMu.Unlock()
	return m.lastRawResp
}

// ClearHistory closes any persistent session so the next Generate starts a fresh
// one, and forgets the last raw response.
func (m *MCP) ClearHistory() {
	m.dropSession()
	m.rawMu.Lock()
	m.lastRawResp = nil
	m.rawMu.Unlock()
}

// Name returns the generator's fully qualified name.
func (m *MCP) Name() string { return "mcp.MCP" }

// Description returns a human-readable description.
func (m *MCP) Description() string {
	return "Model Context Protocol generator (stdio, streamable HTTP, and legacy SSE transports; tool_call and list_tools modes)"
}

// target returns a human-readable identifier of the connection endpoint for
// error messages.
func (m *MCP) target() string {
	if m.cfg.Transport == TransportStdio {
		return strings.TrimSpace(m.cfg.Command + " " + strings.Join(m.cfg.Args, " "))
	}
	return m.cfg.Endpoint
}

// headerTransport injects a fixed set of headers on every outgoing request.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone before mutating: RoundTrippers must not modify the caller's request.
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.base.RoundTrip(clone)
}

// contentText assembles the text of a tool result, concatenating all text
// content blocks and ignoring non-text blocks (images/audio), which the raw JSON
// preserves for hooks that need them.
func contentText(content []mcpsdk.Content) string {
	var parts []string
	for _, c := range content {
		if tc, ok := c.(*mcpsdk.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "")
}

// formatTools renders advertised tools as text for list_tools mode.
func formatTools(tools []*mcpsdk.Tool) string {
	var b strings.Builder
	for i, tool := range tools {
		if tool == nil {
			continue
		}
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("## ")
		b.WriteString(tool.Name)
		if tool.Description != "" {
			b.WriteString("\n")
			b.WriteString(tool.Description)
		}
		if tool.InputSchema != nil {
			if schema, err := json.Marshal(tool.InputSchema); err == nil {
				b.WriteString("\ninput_schema: ")
				b.Write(schema)
			}
		}
	}
	return b.String()
}

// substitute renders a template in a single left-to-right pass so a prompt that
// itself contains a literal placeholder (e.g. "$KEY") is never re-expanded.
// Longer placeholders are ordered first so $INPUT_JSON wins over $INPUT, and
// hook-var names are sorted longest-first for the same reason.
func substitute(tmpl, prompt, apiKey string, hookVars map[string]string) string {
	keys := make([]string, 0, len(hookVars))
	for k := range hookVars {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })

	pairs := make([]string, 0, (len(keys)+3)*2)
	for _, k := range keys {
		pairs = append(pairs, "$"+k, hookVars[k])
	}
	pairs = append(pairs,
		"$INPUT_JSON", jsonEscape(prompt),
		"$INPUT", prompt,
	)
	if apiKey != "" {
		pairs = append(pairs, "$KEY", apiKey)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

// jsonEscape returns s escaped for embedding inside a JSON string literal,
// without the surrounding quotes.
func jsonEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b[1 : len(b)-1])
}

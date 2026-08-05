package mcpprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// AnonSession is a live MCP client session established over a transport that
// carries NONE of the operator's configured credentials. It models the
// unauthenticated attacker: someone who knows the endpoint URL and nothing else.
//
// It deliberately mirrors types.ToolInvoker (ListTools / CallTool with identical
// signatures) so a probe can run the same enumeration and invocation logic
// against the authenticated generator and this anonymous session, then compare —
// which is the whole point. The differential is the finding; neither side alone
// is one.
//
// Credentials are excluded structurally, not by convention: the session is built
// on types.MCPEndpoint.AnonymousHTTPClient(), which strips the header-injection
// middleware while keeping proxy and TLS settings. Sending the operator's token
// would make a correctly-hardened server accept us because we are authenticated,
// not because it is vulnerable, inverting the verdict on exactly the targets the
// probe most needs to get right.
type AnonSession struct {
	sess      *mcpsdk.ClientSession
	cancel    context.CancelFunc
	transport string
}

// ConnectAnonymous establishes an anonymous MCP session against end's endpoint.
//
// The transport is taken from end.Transport(); an empty or "auto" value is
// resolved by trying both HTTP-based transports, preferring the one the endpoint
// path hints at (a path ending in /sse means legacy HTTP+SSE). Trying both
// matters because a helper that spoke only streamable HTTP would silently skip
// every legacy-SSE server and report nothing — a false negative dressed as a
// clean scan.
//
// An error means the target refused the anonymous session (or is unreachable),
// which is the SAFE signal for an unauthenticated-access probe. Callers must
// record it as evidence rather than discard it: "the server refused us" and "we
// never asked" have to stay distinguishable.
func ConnectAnonymous(ctx context.Context, end types.MCPEndpoint, timeout time.Duration) (*AnonSession, error) {
	endpoint := end.EndpointURL()
	if endpoint == "" {
		return nil, errors.New("mcpprobe: target exposes no endpoint URL; cannot open an anonymous session")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("mcpprobe: endpoint %q is not HTTP-based; anonymous session unsupported", endpoint)
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var errs []error
	for _, kind := range anonTransportOrder(end.Transport(), endpoint) {
		// A fresh anonymous client per attempt: AnonymousHTTPClient hands over
		// ownership, and a client consumed by a failed handshake must not be reused.
		sess, cancel, err := connectAnonTransport(ctx, transportFor(kind, endpoint, end.AnonymousHTTPClient()), timeout)
		if err == nil {
			return &AnonSession{sess: sess, cancel: cancel, transport: kind}, nil
		}
		// The caller's own cancellation is not an "unsupported transport" signal;
		// surface it instead of masking it behind another attempt.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("mcpprobe: anonymous connect to %s cancelled: %w", endpoint, ctx.Err())
		}
		errs = append(errs, fmt.Errorf("%s: %w", kind, err))
	}
	return nil, fmt.Errorf("mcpprobe: anonymous connect to %s failed: %w", endpoint, errors.Join(errs...))
}

// anonTransportOrder returns the transports to attempt, in order. An explicit
// declared transport is honoured exactly; "auto"/"" tries both, preferring the
// one the endpoint path hints at.
func anonTransportOrder(declared, endpoint string) []string {
	switch declared {
	case "http", "sse":
		return []string{declared}
	}
	if endpointLooksSSE(endpoint) {
		return []string{"sse", "http"}
	}
	return []string{"http", "sse"}
}

// endpointLooksSSE reports whether the endpoint path ends in /sse, the
// conventional path for a legacy HTTP+SSE MCP stream.
func endpointLooksSSE(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/sse")
}

// transportFor builds the SDK transport for one connection attempt.
func transportFor(kind, endpoint string, client *http.Client) mcpsdk.Transport {
	if kind == "sse" {
		return &mcpsdk.SSEClientTransport{Endpoint: endpoint, HTTPClient: client}
	}
	return &mcpsdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client}
}

// connectAnonTransport performs the handshake under an independent timeout.
//
// The session context is derived from context.Background(), not the caller's:
// the transport's read loop must outlive the connect call, exactly as the mcp
// generator's connectTransport does. Close() cancels it.
func connectAnonTransport(ctx context.Context, transport mcpsdk.Transport, timeout time.Duration) (*mcpsdk.ClientSession, context.CancelFunc, error) {
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "augustus-anonymous", Version: "1.0"}, nil)

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

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case r := <-ch:
		if r.err != nil {
			sessCancel()
			return nil, nil, r.err
		}
		return r.sess, sessCancel, nil
	case <-timer.C:
		sessCancel()
		<-ch // let the aborted Connect goroutine finish before returning
		return nil, nil, fmt.Errorf("handshake timed out after %s", timeout)
	case <-ctx.Done():
		sessCancel()
		<-ch
		return nil, nil, ctx.Err()
	}
}

// Transport reports the transport the anonymous session actually connected over.
func (s *AnonSession) Transport() string { return s.transport }

// ListTools enumerates the target's advertised tools in the canonical
// Conversation.Tools wire shape, matching types.ToolInvoker.ListTools so the
// authenticated and anonymous catalogs are directly comparable.
//
// Pagination is deliberately NOT followed here. This session exists to answer
// "does the endpoint serve an unauthenticated caller at all", and the first page
// settles that; a probe must never draw a per-tool conclusion from this catalog
// without accounting for truncation.
func (s *AnonSession) ListTools(ctx context.Context) ([]map[string]any, error) {
	res, err := s.sess.ListTools(ctx, &mcpsdk.ListToolsParams{})
	if err != nil {
		return nil, err
	}
	return toolsToMaps(res.Tools), nil
}

// CallTool invokes the named tool over the anonymous session. Matches
// types.ToolInvoker.CallTool: a tool-level (application) error surfaces via
// ToolResult.IsError — itself a valid security observation — and only
// transport/protocol failures return an error.
func (s *AnonSession) CallTool(ctx context.Context, name string, args map[string]any) (types.ToolResult, error) {
	res, err := s.sess.CallTool(ctx, &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return types.ToolResult{}, err
	}
	raw, _ := json.Marshal(res)
	return types.ToolResult{Text: contentText(res.Content), Raw: raw, IsError: res.IsError}, nil
}

// Close tears down the session and cancels the context owning its stream.
func (s *AnonSession) Close() {
	if s == nil {
		return
	}
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

// toolsToMaps converts SDK tool descriptors into the canonical
// Conversation.Tools wire shape, carrying the safety annotations so toolpolicy
// can gate destructive tools on an anonymously-obtained catalog exactly as it
// does on the authenticated one.
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
		if a := annotationsFrom(t.Annotations); a != nil {
			tm["annotations"] = *a
		}
		out = append(out, tm)
	}
	return out
}

// annotationsFrom converts SDK tool annotations to the shared type consumers
// expect (a value, matching both the live-enumeration and recon-inventory paths).
func annotationsFrom(a *mcpsdk.ToolAnnotations) *types.MCPToolAnnotations {
	if a == nil {
		return nil
	}
	return &types.MCPToolAnnotations{
		ReadOnly:    a.ReadOnlyHint,
		Destructive: a.DestructiveHint,
		Idempotent:  a.IdempotentHint,
		OpenWorld:   a.OpenWorldHint,
		Title:       a.Title,
	}
}

// contentText assembles the text content of a tool result.
func contentText(content []mcpsdk.Content) string {
	var b strings.Builder
	for _, c := range content {
		if tc, ok := c.(*mcpsdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// readOnlyToolNameRE matches tool names that conventionally denote a read-only
// operation. It is a CONVENTIONAL vocabulary — verbs any practitioner would read
// as "this only observes" — with nothing specific to a server or benchmark.
//
// It exists because most servers ship no annotations at all, so annotation-only
// gating would leave the invocation proof with no tool to call on the majority of
// real targets.
var readOnlyToolNameRE = regexp.MustCompile(
	`(?i)(^|[-_.])(get|list|read|show|search|describe|find|query|fetch|view|lookup|info|count|check|status|whoami|ping|head|inspect|summar\w*|report|stat|exists|resolve|validate|test)($|[-_.])`)

// IsReadOnlyTool reports whether a tool is safe to invoke as the unauthenticated
// invocation proof.
//
// It is deliberately CONSERVATIVE, and the asymmetry is the point: a server
// annotation is authoritative in both directions, but in its absence only a
// recognised read-only name qualifies. An unrecognised name is treated as
// potentially state-changing, because the enumeration finding already carries the
// headline verdict — so this probe never needs to mutate a customer's state to
// make its case, and a wrong guess here would be far more costly than a missed
// invocation proof.
func IsReadOnlyTool(tm map[string]any) bool {
	if ann, ok := tm["annotations"].(types.MCPToolAnnotations); ok {
		if ann.ReadOnly {
			return true
		}
		// An explicit non-destructive hint on a non-read-only tool still means it
		// writes something; only ReadOnly clears a tool for invocation.
		if ann.IsDestructive() {
			return false
		}
	}
	name, _ := tm["name"].(string)
	if name == "" {
		return false
	}
	return readOnlyToolNameRE.MatchString(name)
}

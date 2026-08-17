package types

import (
	"context"
	"errors"
)

// ToolInvoker is an OPTIONAL interface a Generator implements when its target
// exposes a directly-invokable tool surface (e.g. an MCP server) rather than
// only an LLM chat completion. It lets probes discover the target's real tools
// and call them directly, which is the basis for authorization and
// injection-into-a-sink testing against tool backends.
//
// This is distinct from the model-facing tool wire layer (attempt.Conversation.Tools
// / attempt.Message.ToolCalls): that layer presents probe-defined tools TO an LLM
// and observes which the model decides to call (nothing executes). ToolInvoker
// invokes REAL tools that actually execute; the target is the tool backend, not
// the model. A generator may implement both.
//
// Probes type-assert a Generator to ToolInvoker and skip the target when the
// assertion fails, exactly as with VisionCapable / RawResponseProvider.
type ToolInvoker interface {
	// ListTools returns the target's advertised tools in the canonical
	// Conversation.Tools wire shape: one map per tool with "name",
	// "description", and (when present) "parameters" (a JSON-schema object).
	// Reusing this shape avoids a bespoke tool-schema type and lets a discovered
	// catalog feed straight into a Conversation.
	// A truncated enumeration returns the pages gathered so far together with an
	// error wrapping ErrCatalogTruncated, so a caller that ignores the error cannot
	// mistake a partial catalog for the target's whole tool surface.
	ListTools(ctx context.Context) ([]map[string]any, error)

	// CallTool invokes the named tool with the given arguments and returns its
	// result. A tool-level (application) error is reported via ToolResult.IsError,
	// not as a Go error; only transport/protocol failures return an error.
	CallTool(ctx context.Context, name string, args map[string]any) (ToolResult, error)
}

// ErrCatalogTruncated reports that a tool-catalog enumeration stopped early with
// pages left unfetched — a repeated cursor, a page cap, a wall-clock budget, or a
// volume bound. ListTools implementations wrap it; consumers test with errors.Is.
//
// It is deliberately distinct from an ordinary list failure. An unreachable target
// yields no catalog and a consumer may reasonably skip it. A TRUNCATED catalog
// yields a plausible-looking prefix, so treating it as either complete or empty
// lets a server that halts enumeration after a benign prefix be scored as clean —
// the partial-as-complete failure this sentinel exists to make impossible to miss.
var ErrCatalogTruncated = errors.New("types: tool catalog enumeration truncated; results are incomplete")

// ErrCallRefused reports that the call REACHED the target and the target refused
// it — a protocol-level rejection such as invalid parameters or an unknown
// method, answered by the server itself. CallTool implementations wrap it;
// consumers test with errors.Is.
//
// The distinction it draws is the difference between a test and a gap. A payload
// the server rejects at schema validation is a completed test with a negative
// result: the argument was submitted, the server considered it, and the server
// said no. A transport failure is not a test at all — nothing was submitted and
// nothing is known.
//
// Both used to arrive as an undifferentiated error, so both were recorded as the
// probe having failed. Measured against one conditional server, 234 of 540
// attempts were refusals: every one of them a successful test, all of them
// counted as errors, and the whole scan reported as not reflecting the target's
// safety. The pressure that creates is to stop treating errors as significant,
// which is exactly how a genuine "we never tested this" becomes a silent pass.
var ErrCallRefused = errors.New("types: the target refused the call")

// ToolResult is the outcome of a single ToolInvoker.CallTool. It has no existing
// equivalent (Message.ToolCalls represents a tool *call*, not its result).
type ToolResult struct {
	// Text is the assembled text content of the result.
	Text string
	// Raw is the raw JSON of the underlying result, for callers (e.g. runtime
	// hooks) that need the full structured payload.
	Raw []byte
	// IsError reports a tool-level (application) error, e.g. "access denied" —
	// a valid security observation, not a transport failure.
	IsError bool
}

package types

import "context"

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
	ListTools(ctx context.Context) ([]map[string]any, error)

	// CallTool invokes the named tool with the given arguments and returns its
	// result. A tool-level (application) error is reported via ToolResult.IsError,
	// not as a Go error; only transport/protocol failures return an error.
	CallTool(ctx context.Context, name string, args map[string]any) (ToolResult, error)
}

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

package types

import "context"

// MCPPrimitiveReader is an OPTIONAL interface a Generator implements when its
// target exposes the MCP content-bearing primitives BEYOND tools: resources
// (resources/read) and prompt templates (prompts/get).
//
// It is distinct from both sibling interfaces. ToolInvoker covers only the tool
// surface (tools/list + tools/call). MCPReconnaissance enumerates the whole
// catalog — resource URIs, resource templates, prompt names and their argument
// lists — but never fetches the CONTENT behind an entry, which is precisely what
// this interface adds: the catalog says a resource exists, this says what reading
// it returns. A generator may implement all three.
//
// Both calls are outbound client requests, the same direction as tools/call, so
// implementing them introduces no new protocol direction. Server-initiated
// callbacks (sampling/createMessage, elicitation/create) are inbound and remain a
// separate, unimplemented capability.
//
// Probes type-assert a Generator to MCPPrimitiveReader and skip — or fail loud on
// — a target that does not implement it, exactly as with ToolInvoker and
// VisionCapable.
type MCPPrimitiveReader interface {
	// ReadResource fetches the content behind one resource URI.
	//
	// Unlike ToolInvoker.CallTool there is no application-level error flag: the
	// MCP resources/read call reports failure (unknown URI, denied path, read
	// error) as a JSON-RPC error, so a refusal arrives as a Go error rather than
	// as a result with a flag set. Callers testing for an unrestricted read sink
	// must therefore treat "error" as the denial signal and a returned body as
	// the acceptance signal.
	ReadResource(ctx context.Context, uri string) (MCPResourceResult, error)

	// GetPrompt renders one prompt template with the supplied arguments.
	//
	// Arguments are string-typed because the MCP spec declares prompt arguments
	// as a name/description/required triple with no JSON schema — hence
	// map[string]string here rather than the map[string]any CallTool takes. As
	// with ReadResource, a rejected render surfaces as a Go error.
	GetPrompt(ctx context.Context, name string, args map[string]string) (MCPPromptResult, error)
}

// MCPResourceResult is the outcome of a single MCPPrimitiveReader.ReadResource.
// A resources/read response may carry several content blocks (the spec permits a
// single URI to expand to multiple contents); Text is their assembled text so a
// probe can scan one string, while Raw preserves the full structured payload for
// callers that need the individual blocks or the binary Blob fields.
type MCPResourceResult struct {
	// URI is the resource URI that was requested.
	URI string
	// Text is the assembled text content of every returned block.
	Text string
	// MIMEType is the MIME type of the first block that declared one.
	MIMEType string
	// Raw is the raw JSON of the underlying ReadResourceResult.
	Raw []byte
	// Blocks counts the content blocks the server returned. A read that
	// legitimately resolves to nothing (zero blocks) is distinguishable from one
	// that returned an empty-string body.
	Blocks int
}

// MCPPromptResult is the outcome of a single MCPPrimitiveReader.GetPrompt. Text
// is the assembled text of every rendered message, which is what an MCP host
// would place into the model's context — and therefore what a probe scores.
type MCPPromptResult struct {
	// Name is the prompt template that was rendered.
	Name string
	// Description is the server-supplied description of the rendered prompt.
	Description string
	// Text is the assembled text content of every rendered message.
	Text string
	// Raw is the raw JSON of the underlying GetPromptResult.
	Raw []byte
	// Messages counts the rendered messages the server returned.
	Messages int
}

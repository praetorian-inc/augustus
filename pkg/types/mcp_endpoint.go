package types

// MCPEndpoint is an OPTIONAL interface a Generator implements when its target
// is reached over an HTTP-based MCP transport whose URL can be exposed to
// transport-layer probes. It exists so probes that need the raw endpoint (for
// DNS-rebinding, TLS, session-hijacking, and OAuth checks) don't have to
// depend on an internal generator package or duplicate configuration surface.
//
// A generator whose target has no meaningful URL (or that only speaks a local
// subprocess transport) simply does not implement it. Probes type-assert and
// skip the target when the assertion fails, mirroring ToolInvoker /
// MCPReconnaissance.
type MCPEndpoint interface {
	// EndpointURL returns the fully qualified URL the generator connects to
	// (e.g. https://mcp.example.com/rpc). Empty string means no URL surface.
	EndpointURL() string
	// Transport returns the connected transport kind ("http", "sse", ...),
	// mirroring MCPInventory.Transport. Empty string means unknown.
	Transport() string
}

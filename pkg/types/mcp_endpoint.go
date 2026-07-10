package types

import "net/http"

// MCPEndpoint is an OPTIONAL interface a Generator implements when its target
// is reached over an HTTP-based MCP transport. It exists so transport-layer
// probes (DNS-rebinding, session-hijacking, TLS/OAuth checks) can send
// bespoke HTTP requests — bypassing the MCP protocol layer — WITHOUT
// re-implementing the generator's outbound routing concerns (proxy, TLS
// options, auth headers, user agent). Anything a probe needs to know about
// how to reach the target lives here.
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
	// HTTPClient returns a freshly constructed http.Client whose Transport
	// carries every outbound routing setting the generator was configured
	// with — proxy (Burp interception), TLS skip-verify, injected headers,
	// per-request hook-var substitution. Each call returns an independent
	// client, so probes are free to mutate Timeout / CheckRedirect / etc.
	// on the returned value without affecting other probes or the generator
	// itself. Ownership of the client passes to the caller.
	//
	// Probes MUST use this instead of building their own http.Client, so
	// that `proxy: http://127.0.0.1:8080` in the generator config just
	// works — you should never see a probe's requests bypass the operator's
	// interception proxy, and you should never have to duplicate proxy/TLS
	// config on the probe side.
	HTTPClient() *http.Client
}

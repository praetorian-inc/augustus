package types

import (
	"net/http"
	"net/url"
)

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
	// AnonymousHTTPClient returns a client with the same outbound
	// plumbing as HTTPClient (proxy, TLS, request timeout) but WITHOUT
	// the header-injection middleware that stamps configured auth /
	// api-key / scan-tag headers on every request. Probes that model an
	// untrusted / off-path attacker (DNS rebinding, session hijack,
	// pre-auth CSRF) MUST use this — sending the operator's bearer
	// token as an attacker inverts the verdict on hardened servers
	// (they'll accept because we're authenticated, not because they're
	// vulnerable).
	//
	// Each call returns an independent client, same ownership contract
	// as HTTPClient.
	AnonymousHTTPClient() *http.Client
	// ProxyURL returns the outbound proxy the generator is configured to
	// route through, or nil when no explicit proxy is in play. Probes that
	// make security claims sensitive to connection-lifetime semantics
	// (SSE session-hijack replay tests, streaming session-timeout checks)
	// inspect this to suppress findings that a persistent-connection
	// intermediary would generate as artifacts rather than as real target
	// weaknesses. This is deliberately just the explicit config value —
	// transparent / env-var / PAC proxies aren't reported here; callers
	// who need to worry about those must check ProxyFromEnvironment
	// themselves.
	ProxyURL() *url.URL
}

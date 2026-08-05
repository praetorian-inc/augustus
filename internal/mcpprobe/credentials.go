package mcpprobe

// CredentialReporter is an OPTIONAL capability a Generator declares when it can
// report WHETHER the operator configured credentials for the target — never what
// they are.
//
// It exists because an unauthenticated-access finding is only meaningful as a
// DIFFERENTIAL. "The anonymous session worked" is trivially true against a server
// the operator never supplied credentials for, so a probe firing on that alone is
// a false-positive generator that would discredit itself on its first engagement.
// The defensible claim is narrower: an authentication boundary WAS configured and
// the target served an equivalent anonymous caller anyway — the boundary is
// decorative.
//
// Answering that requires the operator's intent, and no amount of target-side
// observation supplies it: a server with no authentication is indistinguishable
// on the wire from a server whose authentication layer never runs. Nor can it be
// recovered from the two clients types.MCPEndpoint already exposes — HTTPClient
// and AnonymousHTTPClient differ only in a RoundTripper the caller cannot see
// inside, and the credential-injecting transport deliberately withholds headers
// from any host other than the configured endpoint, so a probe-local sink
// observes nothing. Hence an explicit declaration.
//
// Implementations return the NAMES of the credential-bearing request headers they
// would inject, never the values: names establish the precondition and explain
// the finding while keeping operator secrets out of attempt metadata, JSONL
// output, and rendered reports.
//
// Satisfaction is structural (Go implicit interfaces), so the generator package
// need not import this one. A generator that cannot report this simply lacks the
// method; probes type-assert and treat a failed assertion — or an empty result —
// as "cannot assess", which is a SKIP with a stated reason, never a clean pass.
// This mirrors types.ToolInvoker / MCPReconnaissance / MCPEndpoint: capability is
// declared structurally and an undeclared capability is a skip, not an error.
type CredentialReporter interface {
	// ConfiguredCredentialHeaders returns the sorted names of the request
	// headers the generator injects that carry operator-supplied credential
	// material. Empty or nil means no authentication boundary was configured for
	// this target, so anonymous success proves nothing about it.
	ConfiguredCredentialHeaders() []string
}

// Package mcptransport provides transport-layer security probes for MCP
// HTTP endpoints. These probes bypass the MCP protocol layer entirely
// and issue raw HTTP against the target, testing properties of the HTTP
// endpoint itself (Origin/Host validation, session-id quality, session
// lifetime) that no MCP tool invocation could reach.
//
// It is the sibling of `internal/probes/mcptool/`, which houses probes
// that go THROUGH the MCP protocol via types.ToolInvoker to test tool-
// backend behaviour (injection sinks, SSRF, path traversal). The two
// packages target genuinely different surfaces and share only small
// utility helpers; keeping them separate makes the interface each
// probe requires visible at the import layer.
//
// Every probe in this package type-asserts a target generator as
// types.MCPEndpoint and reads EndpointURL / Transport / HTTPClient /
// AnonymousHTTPClient / ProxyURL from it. Targets that don't implement
// MCPEndpoint are silently skipped.
package mcptransport

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// (See mcptransport_test.go for the plainGen test stub — a Generator
// that intentionally implements NEITHER ToolInvoker NOR MCPEndpoint,
// used to exercise the "target does not support the required
// interface" fallback paths.)

// randToken returns a random 16-hex-char token used for canary URLs and
// per-run nonces in the probes' payloads. Duplicated from
// internal/probes/mcptool/mcptool.go rather than shared via a common
// util package — it's an 8-line function and cross-package imports for
// utilities of this size don't earn their keep.
func randToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "augfallback000000"
	}
	return hex.EncodeToString(b)
}

// metaBool reads a bool attempt-metadata value tolerating the JSON
// round-trip that reduces bool to any.
func metaBool(a *attempt.Attempt, key string) bool {
	raw, ok := a.GetMetadata(key)
	if !ok {
		return false
	}
	b, _ := raw.(bool)
	return b
}

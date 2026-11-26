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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

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

// buildToolsListPayload constructs a JSON-RPC 2.0 tools/list request with
// the given _meta fields. Used by the MetadataInjection and
// CapabilityEscalation probes to craft requests with varied client
// self-assertions.
func buildToolsListPayload(meta map[string]any) ([]byte, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{"_meta": meta},
	}
	return json.Marshal(payload)
}

// extractToolNames parses a JSON-RPC 2.0 response and extracts tool names
// from the result.tools array, returning them sorted. An error envelope or
// missing result is an error.
func extractToolNames(body []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty response body")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC: %w", err)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, fmt.Errorf("server returned error: %s", string(envelope.Error))
	}
	if len(envelope.Result) == 0 {
		return nil, fmt.Errorf("no result in response")
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return nil, fmt.Errorf("parse tools result: %w", err)
	}
	names := make([]string, 0, len(result.Tools))
	for _, t := range result.Tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names, nil
}

// toolCatalogsEqual reports whether two sorted tool name slices are identical.
func toolCatalogsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

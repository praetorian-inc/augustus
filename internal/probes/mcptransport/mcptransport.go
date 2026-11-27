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
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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

// extractToolNames parses a JSON-RPC 2.0 response body (plain JSON or
// SSE-framed) and extracts tool names from the result.tools array,
// returned sorted.
//
// Returns a *serverRefusedError when the envelope carries a JSON-RPC
// error field, and a regular error for parse failures or paginated
// responses (nextCursor present).
func extractToolNames(body []byte, contentType string) ([]string, error) {
	jsonBody, err := jsonFromResponse(body, contentType)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(jsonBody, &envelope); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC: %w", err)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, &serverRefusedError{msg: string(envelope.Error)}
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil, fmt.Errorf("no result in response")
	}

	var shape struct {
		Tools      json.RawMessage `json:"tools"`
		NextCursor string          `json:"nextCursor"`
	}
	if err := json.Unmarshal(envelope.Result, &shape); err != nil {
		return nil, fmt.Errorf("parse tools result: %w", err)
	}
	if shape.NextCursor != "" {
		return nil, &paginatedResponseError{cursor: shape.NextCursor}
	}
	if string(shape.Tools) == "null" {
		return []string{}, nil
	}
	if len(shape.Tools) == 0 {
		return nil, &nonToolsResponseError{}
	}

	var tools []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(shape.Tools, &tools); err != nil {
		return nil, fmt.Errorf("parse tools array: %w", err)
	}

	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names, nil
}

// serverRefusedError indicates the server returned a JSON-RPC error
// envelope — it engaged with the request but explicitly refused it.
type serverRefusedError struct {
	msg string
}

func (e *serverRefusedError) Error() string {
	return fmt.Sprintf("server returned JSON-RPC error: %s", e.msg)
}

// paginatedResponseError indicates the tools/list response includes a
// nextCursor, meaning the catalog is split across pages. Single-request
// differential comparison is unreliable against paginated catalogs.
type paginatedResponseError struct {
	cursor string
}

func (e *paginatedResponseError) Error() string {
	return fmt.Sprintf("tools/list response is paginated (nextCursor: %q); single-request comparison is unreliable", e.cursor)
}

// nonToolsResponseError indicates the JSON-RPC result was valid but did
// not contain a tools array — the server likely routed the request to a
// different method handler (e.g. resources/list instead of tools/list).
type nonToolsResponseError struct{}

func (e *nonToolsResponseError) Error() string {
	return "response result does not contain a tools array (not a tools/list response)"
}

// jsonFromResponse extracts JSON from a response body, handling both
// plain JSON (application/json) and SSE-framed (text/event-stream)
// responses.
func jsonFromResponse(body []byte, contentType string) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty response body")
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return extractSSEJSON(body)
	}
	return trimmed, nil
}

// extractSSEJSON finds the JSON-RPC response in an SSE-framed response by
// scanning for data: lines that contain a response envelope (with "result"
// or "error" field). Notifications and other non-response messages are
// skipped. The scanner buffer is sized to maxResponseBody so large tool
// catalogs are not silently truncated by the default 64 KiB token limit.
func extractSSEJSON(body []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), maxResponseBody)
	for scanner.Scan() {
		line := scanner.Text()
		var data string
		switch {
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case strings.HasPrefix(line, "data:"):
			data = strings.TrimPrefix(line, "data:")
		default:
			continue
		}
		data = strings.TrimSpace(data)
		if len(data) == 0 || data[0] != '{' {
			continue
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal([]byte(data), &envelope) != nil {
			continue
		}
		hasResult := len(envelope.Result) > 0 && string(envelope.Result) != "null"
		hasError := len(envelope.Error) > 0 && string(envelope.Error) != "null"
		if hasResult || hasError {
			return []byte(data), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan SSE response: %w", err)
	}
	return nil, fmt.Errorf("no JSON-RPC response found in SSE stream")
}

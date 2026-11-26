package mcptransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// differentialVariant describes one spoofed _meta configuration to test.
type differentialVariant struct {
	class   string
	label   string
	meta    map[string]any
	headers map[string]string
}

// toolsListResult holds the outcome of a single tools/list request.
type toolsListResult struct {
	tools      []string
	transcript string
	refused    bool
	err        error
}

// sweepParams configures a differential sweep against an MCP endpoint.
type sweepParams struct {
	probeName    string
	detectorName string
	endpoint     string
	client       *http.Client
	baselineMeta map[string]any
	variants     []differentialVariant
}

// maxResponseBody is the maximum response body size read from a tools/list
// request. MCP servers with large tool catalogs and input schemas can
// produce responses well over 64 KiB.
const maxResponseBody = 2 * 1024 * 1024

// initSweep validates the endpoint and returns the HTTP client. Returns
// an empty endpoint to signal "skip this target".
func initSweep(probeName string, endpointOverride string, timeout time.Duration, gen types.Generator) (string, *http.Client, error) {
	endpoint := resolveEndpointURL(endpointOverride, gen)
	if endpoint == "" {
		return "", nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", nil, fmt.Errorf("%s: parse endpoint %q: %w", probeName, endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn(probeName+": skipping non-HTTP transport", "endpoint", endpoint)
		return "", nil, nil
	}
	client := borrowAuthHTTPClient(timeout, gen)
	return endpoint, client, nil
}

// resolveEndpointURL returns the endpoint URL from an explicit override
// or from the generator's MCPEndpoint interface.
func resolveEndpointURL(override string, gen types.Generator) string {
	if override != "" {
		return override
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// borrowAuthHTTPClient returns the generator's HTTP client with the given
// timeout. These probes model a connected but malicious MCP client, so
// they use the authenticated HTTPClient (unlike OriginValidation which
// models a browser attacker).
func borrowAuthHTTPClient(timeout time.Duration, gen types.Generator) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	noRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if end, ok := gen.(types.MCPEndpoint); ok {
		client := end.HTTPClient()
		client.Timeout = timeout
		client.CheckRedirect = noRedirect
		return client
	}
	return &http.Client{Timeout: timeout, CheckRedirect: noRedirect}
}

// runDifferentialSweep sends a baseline tools/list and compares against
// each variant. Returns one attempt per request (baseline + variants).
func runDifferentialSweep(ctx context.Context, params sweepParams) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	baseResult := sendToolsListRequest(ctx, params.client, params.endpoint, params.baselineMeta, nil)
	baseAttempt := recordSweepAttempt(params, "baseline", "honest _meta baseline", nil, baseResult, false)
	attempts = append(attempts, baseAttempt)

	if baseResult.err != nil || baseResult.refused {
		slog.Info("differential sweep: baseline failed or refused; cannot compare variants",
			"probe", params.probeName, "endpoint", params.endpoint, "err", baseResult.err)
		return attempts
	}

	for _, v := range params.variants {
		varResult := sendToolsListRequest(ctx, params.client, params.endpoint, v.meta, v.headers)
		a := recordSweepAttempt(params, v.class, v.label, baseResult.tools, varResult, true)
		attempts = append(attempts, a)
	}

	return attempts
}

// sendToolsListRequest sends a tools/list JSON-RPC request with the given
// _meta and optional extra HTTP headers. It distinguishes transport errors
// from server refusals (HTTP 4xx, JSON-RPC error envelopes).
func sendToolsListRequest(ctx context.Context, client *http.Client, endpoint string, meta map[string]any, extraHeaders map[string]string) toolsListResult {
	payload, err := buildToolsListPayload(meta)
	if err != nil {
		return toolsListResult{err: fmt.Errorf("build payload: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return toolsListResult{err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("mcp-protocol-version", "2026-07-28")
	req.Header.Set("mcp-method", "tools/list")

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return toolsListResult{err: fmt.Errorf("POST %s: %w", endpoint, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	transcript := fmt.Sprintf("POST %s -> HTTP %d\nContent-Type: %s\n%s",
		endpoint, resp.StatusCode, resp.Header.Get("Content-Type"), string(body))

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return toolsListResult{transcript: transcript, refused: true}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return toolsListResult{
			transcript: transcript,
			err:        fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body)),
		}
	}

	contentType := resp.Header.Get("Content-Type")
	tools, err := extractToolNames(body, contentType)
	if err != nil {
		var refused *serverRefusedError
		if errors.As(err, &refused) {
			return toolsListResult{transcript: transcript, refused: true}
		}
		return toolsListResult{transcript: transcript, err: fmt.Errorf("extract tools: %w", err)}
	}
	return toolsListResult{tools: tools, transcript: transcript}
}

// recordSweepAttempt creates an attempt from a sweep result.
func recordSweepAttempt(params sweepParams, class, label string, baseline []string, result toolsListResult, isVariant bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] %s", class, label))
	a.Probe = params.probeName
	a.Detector = params.detectorName
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.Metadata[attempt.MetadataKeyMetadataInjectionBaselineTools] = len(baseline)

	if result.err != nil {
		a.SetError(result.err)
		return a
	}

	if result.refused {
		a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = false
		a.AddOutput(fmt.Sprintf("Server refused request for %s (non-differential: server rejected spoofed input).\n\n%s",
			label, result.transcript))
		a.Complete()
		return a
	}

	a.Metadata[attempt.MetadataKeyMetadataInjectionVariantTools] = len(result.tools)

	if isVariant {
		differential := !slices.Equal(baseline, result.tools)
		a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = differential
		if differential {
			a.AddOutput(fmt.Sprintf("Server returned different tools for %s.\n"+
				"Baseline: %d tools %v\nVariant:  %d tools %v\n\n%s",
				label, len(baseline), baseline, len(result.tools), result.tools, result.transcript))
		} else {
			a.AddOutput(fmt.Sprintf("Server returned identical tools for %s: %d tools.\n\n%s",
				label, len(result.tools), result.transcript))
		}
	} else {
		a.AddOutput(fmt.Sprintf("Baseline tools/list returned %d tools: %v\n\n%s",
			len(result.tools), result.tools, result.transcript))
	}
	a.Complete()
	return a
}

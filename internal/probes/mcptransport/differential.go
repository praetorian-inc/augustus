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
	tools       []string
	transcript  string
	refused     bool
	wrongMethod bool // valid JSON-RPC result but not a tools/list response
	err         error
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
// an empty endpoint to signal "skip this target". Legacy SSE targets
// (transport == "sse") are skipped because they serve GET /sse, not
// POST JSON-RPC. Pre-2026-07-28 sessions are skipped because they
// require an initialize handshake the probe does not perform.
func initSweep(ctx context.Context, probeName string, endpointOverride string, timeout time.Duration, gen types.Generator) (string, *http.Client, error) {
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok && mcpEnd.Transport() == "sse" {
		slog.Warn(probeName+": skipping legacy SSE transport (requires GET, not POST JSON-RPC)",
			"endpoint", mcpEnd.EndpointURL())
		return "", nil, nil
	}
	if recon, ok := gen.(types.MCPReconnaissance); ok {
		if inv, err := recon.MCPInventory(ctx); err == nil && inv.ProtocolVersion != "" && inv.ProtocolVersion < "2026-07-28" {
			slog.Warn(probeName+": skipping pre-2026-07-28 session (requires stateless tools/list)",
				"endpoint", resolveEndpointURL(endpointOverride, gen),
				"negotiatedVersion", inv.ProtocolVersion)
			return "", nil, nil
		}
	}
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
//
// The sweep includes a stability check: the baseline is re-sent after all
// variants, and if the catalog changed between the two baselines, all
// variant attempts are marked inconclusive.
func runDifferentialSweep(ctx context.Context, params sweepParams) []*attempt.Attempt {
	var attempts []*attempt.Attempt

	baseResult := sendToolsListRequest(ctx, params.client, params.endpoint, params.baselineMeta, nil)

	if baseResult.err != nil {
		var pgErr *paginatedResponseError
		if errors.As(baseResult.err, &pgErr) {
			a := recordInconclusiveBaseline(params, baseResult,
				"tools/list response is paginated; single-request comparison is unreliable")
			attempts = append(attempts, a)
			slog.Info("differential sweep: baseline paginated; cannot compare variants",
				"probe", params.probeName, "endpoint", params.endpoint)
			return attempts
		}
		a := recordErroredBaseline(params, baseResult)
		attempts = append(attempts, a)
		slog.Info("differential sweep: baseline failed; cannot compare variants",
			"probe", params.probeName, "endpoint", params.endpoint, "err", baseResult.err)
		return attempts
	}

	if baseResult.refused || baseResult.wrongMethod {
		reason := "server rejected honest _meta request (cannot establish reference catalog)"
		if baseResult.wrongMethod {
			reason = "baseline tools/list returned a non-tools result (server misconfigured)"
		}
		a := recordInconclusiveBaseline(params, baseResult, reason)
		attempts = append(attempts, a)
		slog.Info("differential sweep: baseline refused or wrong method; cannot compare variants",
			"probe", params.probeName, "endpoint", params.endpoint)
		return attempts
	}

	baseAttempt := recordBaselineAttempt(params, baseResult)
	attempts = append(attempts, baseAttempt)

	var variantAttempts []*attempt.Attempt
	for _, v := range params.variants {
		varResult := sendToolsListRequest(ctx, params.client, params.endpoint, v.meta, v.headers)
		a := recordVariantAttempt(params, v.class, v.label, baseResult.tools, varResult)
		variantAttempts = append(variantAttempts, a)
		attempts = append(attempts, a)
	}

	// Stability check: re-send baseline and verify catalog hasn't changed.
	baseResult2 := sendToolsListRequest(ctx, params.client, params.endpoint, params.baselineMeta, nil)
	if baseResult2.err != nil || baseResult2.refused || baseResult2.wrongMethod || !slices.Equal(baseResult.tools, baseResult2.tools) {
		for _, a := range variantAttempts {
			a.Metadata[attempt.MetadataKeyInconclusive] = true
			a.Metadata[attempt.MetadataKeyInconclusiveReason] = "catalog changed between identical baseline requests; differential results are unreliable"
		}
		slog.Info("differential sweep: catalog unstable; marking variants inconclusive",
			"probe", params.probeName, "endpoint", params.endpoint)
	}

	return attempts
}

// recordErroredBaseline creates a StatusError attempt for a baseline that
// failed due to a transport error (5xx, network failure).
func recordErroredBaseline(params sweepParams, result toolsListResult) *attempt.Attempt {
	a := attempt.New("[baseline] honest _meta baseline")
	a.Probe = params.probeName
	a.Detector = params.detectorName
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "baseline"
	if result.transcript != "" {
		a.AddOutput(result.transcript)
	}
	a.SetError(result.err)
	return a
}

// recordInconclusiveBaseline creates a completed-but-inconclusive attempt
// for a baseline that was refused (HTTP 4xx, JSON-RPC error) or had a
// paginated response. We could not establish a reference catalog, so the
// scan is a coverage gap — not safe, not error.
func recordInconclusiveBaseline(params sweepParams, result toolsListResult, reason string) *attempt.Attempt {
	a := attempt.New("[baseline] honest _meta baseline")
	a.Probe = params.probeName
	a.Detector = params.detectorName
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "baseline"
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = reason
	if result.transcript != "" {
		a.AddOutput(fmt.Sprintf("Baseline inconclusive: %s\n\n%s", reason, result.transcript))
	} else {
		a.AddOutput(fmt.Sprintf("Baseline inconclusive: %s", reason))
	}
	a.Complete()
	return a
}

// recordBaselineAttempt creates a completed attempt for a successful baseline.
func recordBaselineAttempt(params sweepParams, result toolsListResult) *attempt.Attempt {
	a := attempt.New("[baseline] honest _meta baseline")
	a.Probe = params.probeName
	a.Detector = params.detectorName
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "baseline"
	a.Metadata[attempt.MetadataKeyMetadataInjectionBaselineTools] = len(result.tools)
	a.AddOutput(fmt.Sprintf("Baseline tools/list returned %d tools: %v\n\n%s",
		len(result.tools), result.tools, result.transcript))
	a.Complete()
	return a
}

// recordVariantAttempt creates an attempt for a variant tools/list request.
// Variant errors are recorded as inconclusive (not StatusError) since a
// single variant failure should not turn the entire scan into exit 3.
func recordVariantAttempt(params sweepParams, class, label string, baseline []string, result toolsListResult) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] %s", class, label))
	a.Probe = params.probeName
	a.Detector = params.detectorName
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.Metadata[attempt.MetadataKeyMetadataInjectionBaselineTools] = len(baseline)

	if result.err != nil {
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf("variant request failed: %v", result.err)
		if result.transcript != "" {
			a.AddOutput(fmt.Sprintf("Variant %s failed: %v\n\n%s", label, result.err, result.transcript))
		} else {
			a.AddOutput(fmt.Sprintf("Variant %s failed: %v", label, result.err))
		}
		a.Complete()
		return a
	}

	if result.refused {
		a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = false
		a.AddOutput(fmt.Sprintf("Server refused request for %s (non-differential: server rejected spoofed input).\n\n%s",
			label, result.transcript))
		a.Complete()
		return a
	}

	if result.wrongMethod {
		if class == "header-mismatch" {
			a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = true
			a.Metadata[attempt.MetadataKeyMetadataInjectionNewTools] = 1
			a.Metadata[attempt.MetadataKeyMetadataInjectionBaselineTools] = len(baseline)
			a.AddOutput(fmt.Sprintf("Server returned non-tools/list result for %s (method routing differential).\n\n%s",
				label, result.transcript))
			a.Complete()
			return a
		}
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		a.Metadata[attempt.MetadataKeyInconclusiveReason] = fmt.Sprintf(
			"variant %s returned a result without a tools array; response is uninterpretable", label)
		a.AddOutput(fmt.Sprintf("Server returned non-tools/list result for %s (inconclusive: not a header-mismatch variant).\n\n%s",
			label, result.transcript))
		a.Complete()
		return a
	}

	a.Metadata[attempt.MetadataKeyMetadataInjectionVariantTools] = len(result.tools)

	differential := !slices.Equal(baseline, result.tools)
	a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = differential

	newTools := countNewTools(baseline, result.tools)
	a.Metadata[attempt.MetadataKeyMetadataInjectionNewTools] = newTools

	if differential {
		a.AddOutput(fmt.Sprintf("Server returned different tools for %s.\n"+
			"Baseline: %d tools %v\nVariant:  %d tools %v\nNew tools in variant: %d\n\n%s",
			label, len(baseline), baseline, len(result.tools), result.tools, newTools, result.transcript))
	} else {
		a.AddOutput(fmt.Sprintf("Server returned identical tools for %s: %d tools.\n\n%s",
			label, len(result.tools), result.transcript))
	}
	a.Complete()
	return a
}

// countNewTools returns the number of tools in variant that are not present
// in baseline. Both slices must be sorted.
func countNewTools(baseline, variant []string) int {
	baseSet := make(map[string]bool, len(baseline))
	for _, t := range baseline {
		baseSet[t] = true
	}
	count := 0
	for _, t := range variant {
		if !baseSet[t] {
			count++
		}
	}
	return count
}

// sendToolsListRequest sends a tools/list JSON-RPC request with the given
// _meta and optional extra HTTP headers. It distinguishes transport errors
// from server refusals (HTTP 4xx, JSON-RPC error envelopes).
//
// Transient HTTP errors (429 Too Many Requests, 401 Unauthorized, 408
// Request Timeout) are mapped to err, not refused, because they don't
// indicate the server evaluated and rejected the _meta content.
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return toolsListResult{err: fmt.Errorf("read response from %s: %w", endpoint, err)}
	}
	transcript := fmt.Sprintf("POST %s -> HTTP %d\nContent-Type: %s\n%s",
		endpoint, resp.StatusCode, resp.Header.Get("Content-Type"), string(body))

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		switch resp.StatusCode {
		case http.StatusTooManyRequests,
			http.StatusUnauthorized,
			http.StatusRequestTimeout:
			return toolsListResult{
				transcript: transcript,
				err:        fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body)),
			}
		default:
			return toolsListResult{transcript: transcript, refused: true}
		}
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
		var ntr *nonToolsResponseError
		if errors.As(err, &ntr) {
			return toolsListResult{transcript: transcript, wrongMethod: true}
		}
		return toolsListResult{transcript: transcript, err: fmt.Errorf("extract tools: %w", err)}
	}
	return toolsListResult{tools: tools, transcript: transcript}
}

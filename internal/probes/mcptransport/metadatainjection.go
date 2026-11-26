package mcptransport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptransport.MetadataInjection", NewMetadataInjection)
}

var _ types.ProbeMetadata = (*MetadataInjection)(nil)

// MetadataInjection probes an MCP HTTP endpoint for behaviour that depends on
// client-reported protocol metadata (_meta fields: protocolVersion, clientInfo).
// These fields are unverified self-assertions under the MCP 2026-07-28 spec,
// sent on every request's _meta envelope. A server that changes its tool
// catalog based on the claimed protocol version or client identity is making
// trust decisions on spoofable data.
//
// The probe sends a baseline tools/list with honest _meta, then repeats the
// request with spoofed protocol versions, impersonated client identities, and
// mismatched HTTP headers. If the returned tool catalog differs from the
// baseline, the server is gating functionality on client self-assertions.
type MetadataInjection struct {
	endpointOverride string
	timeout          time.Duration
	nonce            string
}

// NewMetadataInjection constructs the probe.
func NewMetadataInjection(cfg registry.Config) (probes.Prober, error) {
	return &MetadataInjection{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
		nonce:            randToken(),
	}, nil
}

func (p *MetadataInjection) Name() string { return "mcptransport.MetadataInjection" }

var _ types.RiskDescriber = (*MetadataInjection)(nil)

func (p *MetadataInjection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description: "An MCP server changes its behavior based on client-reported protocol metadata " +
			"(_meta fields: protocolVersion, clientInfo), which are unverified self-assertions. " +
			"Trust decisions based on these fields allow a malicious client to unlock hidden " +
			"functionality or bypass restrictions by spoofing its identity or protocol version.",
		Impact: "An attacker connecting to the MCP server can impersonate a trusted client " +
			"(e.g., Claude Desktop) to access restricted tools or resources, or downgrade the " +
			"protocol version to exploit legacy behaviors. Since _meta fields carry no " +
			"authentication, any client can claim to be any other.",
		Recommendation: "Never make authorization or feature-gating decisions based on _meta fields " +
			"(clientInfo, protocolVersion). Use the OAuth token's audience, scope, and claims for " +
			"access control. Treat _meta as informational telemetry only.",
		References: "https://cwe.mitre.org/data/definitions/290.html\nhttps://cwe.mitre.org/data/definitions/287.html",
		Taxonomies: "- cwe: 290\n- cwe: 287",
		CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends a baseline tools/list request with honest _meta fields, then repeats " +
			"the request with spoofed protocol versions, impersonated client identities, and " +
			"mismatched HTTP headers. If the returned tool catalog differs from the baseline for " +
			"any variant, the server is making trust decisions based on unverified client metadata.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the mcptransport.MetadataInjection probe against the affected endpoint via the " +
			"mcp.MCP generator. Compare the tools/list response under the honest baseline with " +
			"the response when clientInfo or protocolVersion is spoofed.",
	}
}

func (p *MetadataInjection) Description() string {
	return "Tests whether an MCP server changes its tool catalog based on spoofed _meta fields " +
		"(protocolVersion, clientInfo) or mismatched HTTP headers. A behavioral differential " +
		"means the server trusts unverified client self-assertions for feature gating."
}

func (p *MetadataInjection) Goal() string {
	return "Determine whether the MCP server gates tool availability on client-reported " +
		"protocol metadata (_meta). Score = 1.0 when the tool catalog changes in response " +
		"to spoofed metadata, 0.0 when the catalog is stable."
}

func (p *MetadataInjection) GetPrimaryDetector() string { return "mcptransport.MetadataInjection" }

func (p *MetadataInjection) GetPrompts() []string {
	return []string{"MCP tools/list with spoofed _meta protocol version, client identity, and mismatched HTTP headers"}
}

// metadataVariant describes one spoofed _meta configuration to test.
type metadataVariant struct {
	class   string
	label   string
	meta    map[string]any
	headers map[string]string // extra HTTP headers for header-mismatch tests
}

// baselineMeta returns the honest _meta fields for the baseline request.
func (p *MetadataInjection) baselineMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name":    "augustus-scan",
			"version": "1.0",
		},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}
}

// variants returns the set of spoofed _meta configurations to test.
func (p *MetadataInjection) variants() []metadataVariant {
	base := p.baselineMeta()
	return []metadataVariant{
		{
			class: "protocol-version-downgrade",
			label: "protocolVersion 2024-11-05 (old spec)",
			meta:  withProtocolVersion(base, "2024-11-05"),
		},
		{
			class: "protocol-version-upgrade",
			label: "protocolVersion 2099-01-01 (future/unknown)",
			meta:  withProtocolVersion(base, "2099-01-01"),
		},
		{
			class: "client-identity-spoof",
			label: "clientInfo claude-desktop (privileged client)",
			meta:  withClientInfo(base, "claude-desktop", "1.0.0"),
		},
		{
			class: "client-identity-spoof",
			label: "clientInfo admin-console (admin tool)",
			meta:  withClientInfo(base, "admin-console", "1.0.0"),
		},
		{
			class: "client-identity-spoof",
			label: fmt.Sprintf("clientInfo %s-scanner (unknown client)", p.nonce[:8]),
			meta:  withClientInfo(base, p.nonce[:8]+"-scanner", "0.0.1"),
		},
		{
			class:   "header-mismatch",
			label:   "mcp-method: resources/list (body says tools/list)",
			meta:    copyMeta(base),
			headers: map[string]string{"mcp-method": "resources/list"},
		},
		{
			class:   "header-mismatch",
			label:   "mcp-protocol-version: 2024-11-05 (body says 2026-07-28)",
			meta:    copyMeta(base),
			headers: map[string]string{"mcp-protocol-version": "2024-11-05"},
		},
	}
}

// Probe resolves the endpoint and runs the metadata injection sweep.
func (p *MetadataInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.MetadataInjection: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("mcptransport.MetadataInjection: skipping non-HTTP transport", "endpoint", endpoint)
		return nil, nil
	}

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}
	var attempts []*attempt.Attempt

	// 1. Baseline: honest _meta.
	baselineMeta := p.baselineMeta()
	baselineTools, baselineResp, baselineErr := p.sendToolsList(ctx, client, endpoint, baselineMeta, nil)
	baseAttempt := p.recordAttempt("baseline", "honest _meta baseline", baselineTools, baselineTools, baselineResp, baselineErr, false)
	attempts = append(attempts, baseAttempt)

	if baselineErr != nil {
		slog.Info("mcptransport.MetadataInjection: baseline failed; cannot compare variants",
			"endpoint", endpoint, "err", baselineErr)
		return attempts, nil
	}

	// 2. Variants.
	for _, v := range p.variants() {
		variantTools, variantResp, variantErr := p.sendToolsList(ctx, client, endpoint, v.meta, v.headers)
		a := p.recordAttempt(v.class, v.label, baselineTools, variantTools, variantResp, variantErr, true)
		attempts = append(attempts, a)
	}

	return attempts, nil
}

// sendToolsList sends a tools/list JSON-RPC request with the given _meta and
// optional extra HTTP headers. Returns the parsed tool names (sorted), the
// raw response body, and any error.
func (p *MetadataInjection) sendToolsList(ctx context.Context, client *http.Client, endpoint string, meta map[string]any, extraHeaders map[string]string) ([]string, string, error) {
	payload, err := buildToolsListPayload(meta)
	if err != nil {
		return nil, "", fmt.Errorf("build payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	transcript := fmt.Sprintf("POST %s -> HTTP %d\nContent-Type: %s\n%s", endpoint, resp.StatusCode, resp.Header.Get("Content-Type"), string(body))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, transcript, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	tools, err := extractToolNames(body)
	if err != nil {
		return nil, transcript, fmt.Errorf("extract tools: %w", err)
	}
	return tools, transcript, nil
}

// recordAttempt creates an attempt from a variant result.
func (p *MetadataInjection) recordAttempt(class, label string, baseline, variant []string, transcript string, err error, isVariant bool) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("[%s] %s", class, label))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.Metadata[attempt.MetadataKeyMetadataInjectionBaselineTools] = len(baseline)

	if err != nil {
		a.SetError(err)
		return a
	}

	a.Metadata[attempt.MetadataKeyMetadataInjectionVariantTools] = len(variant)

	if isVariant {
		differential := !toolCatalogsEqual(baseline, variant)
		a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = differential
		if differential {
			a.AddOutput(fmt.Sprintf("Server returned different tools for %s.\n"+
				"Baseline: %d tools %v\nVariant:  %d tools %v\n\n%s",
				label, len(baseline), baseline, len(variant), variant, transcript))
		} else {
			a.AddOutput(fmt.Sprintf("Server returned identical tools for %s: %d tools.\n\n%s",
				label, len(variant), transcript))
		}
	} else {
		a.AddOutput(fmt.Sprintf("Baseline tools/list returned %d tools: %v\n\n%s",
			len(variant), variant, transcript))
	}
	a.Complete()
	return a
}

// resolveEndpoint returns the endpoint URL from probe config (explicit
// override wins) or from the generator via types.MCPEndpoint.
func (p *MetadataInjection) resolveEndpoint(gen types.Generator) string {
	if p.endpointOverride != "" {
		return p.endpointOverride
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// borrowHTTPClient returns the generator's http.Client with this probe's
// timeout. Unlike the OriginValidation probe (which models a browser
// attacker and strips auth), this probe models a connected but malicious
// MCP client, so it uses the standard HTTPClient.
func (p *MetadataInjection) borrowHTTPClient(gen types.Generator) (*http.Client, error) {
	timeout := p.timeout
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
		return client, nil
	}
	return &http.Client{Timeout: timeout, CheckRedirect: noRedirect}, nil
}

// withProtocolVersion returns a copy of base with the protocol version changed.
func withProtocolVersion(base map[string]any, version string) map[string]any {
	m := copyMeta(base)
	m["io.modelcontextprotocol/protocolVersion"] = version
	return m
}

// withClientInfo returns a copy of base with client info changed.
func withClientInfo(base map[string]any, name, version string) map[string]any {
	m := copyMeta(base)
	m["io.modelcontextprotocol/clientInfo"] = map[string]any{
		"name":    name,
		"version": version,
	}
	return m
}

// copyMeta returns a shallow copy of the _meta map.
func copyMeta(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

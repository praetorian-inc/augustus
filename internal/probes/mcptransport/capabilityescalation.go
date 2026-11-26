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
	probes.Register("mcptransport.CapabilityEscalation", NewCapabilityEscalation)
}

var _ types.ProbeMetadata = (*CapabilityEscalation)(nil)

// CapabilityEscalation probes an MCP HTTP endpoint for behaviour that depends
// on client-declared capabilities (_meta.clientCapabilities). These are
// unverified self-assertions: a client claims what it can handle, not what it
// is authorized to access. A server that exposes different tools depending on
// the declared capabilities is gating functionality on spoofable metadata.
//
// The probe sends a baseline tools/list with empty clientCapabilities, then
// repeats the request declaring elicitation, task extensions, roots, all
// capabilities at once, and bogus capabilities. If the returned tool catalog
// differs from the baseline for any variant, the server uses capability
// declarations for feature gating.
type CapabilityEscalation struct {
	endpointOverride string
	timeout          time.Duration
	nonce            string
}

// NewCapabilityEscalation constructs the probe.
func NewCapabilityEscalation(cfg registry.Config) (probes.Prober, error) {
	return &CapabilityEscalation{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
		nonce:            randToken(),
	}, nil
}

func (p *CapabilityEscalation) Name() string { return "mcptransport.CapabilityEscalation" }

var _ types.RiskDescriber = (*CapabilityEscalation)(nil)

func (p *CapabilityEscalation) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description: "An MCP server exposes different tools or features depending on the client's " +
			"declared capabilities (_meta.clientCapabilities), which are unverified self-assertions. " +
			"A client that claims to support elicitation, tasks, or other extensions can unlock " +
			"functionality the server intended only for capable clients.",
		Impact: "An attacker can claim support for privileged extensions to access additional " +
			"tools or data-collection features the server gates on capability declarations, " +
			"bypassing the intended progressive disclosure model.",
		Recommendation: "Never gate tool availability or server behavior on client-declared " +
			"capabilities. Capabilities describe what the client can handle, not what it is " +
			"authorized to access. Use OAuth scopes for authorization.",
		References: "https://cwe.mitre.org/data/definitions/290.html",
		Taxonomies: "- cwe: 290",
		CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends a baseline tools/list request with empty clientCapabilities, then " +
			"repeats the request declaring elicitation, task extensions, roots, all capabilities " +
			"at once, and bogus capabilities. If the returned tool catalog differs from the " +
			"baseline for any variant, the server gates features on capability self-assertions.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the mcptransport.CapabilityEscalation probe against the affected endpoint " +
			"via the mcp.MCP generator. Compare the tools/list response under the empty-capabilities " +
			"baseline with the response when clientCapabilities is populated.",
	}
}

func (p *CapabilityEscalation) Description() string {
	return "Tests whether an MCP server changes its tool catalog based on client-declared " +
		"capabilities (_meta.clientCapabilities). A behavioral differential means the server " +
		"gates features on unverified client self-assertions rather than on authenticated scopes."
}

func (p *CapabilityEscalation) Goal() string {
	return "Determine whether the MCP server gates tool availability on client-declared " +
		"capabilities. Score = 1.0 when the tool catalog changes in response to spoofed " +
		"capabilities, 0.0 when the catalog is stable."
}

func (p *CapabilityEscalation) GetPrimaryDetector() string {
	return "mcptransport.CapabilityEscalation"
}

func (p *CapabilityEscalation) GetPrompts() []string {
	return []string{"MCP tools/list with varied clientCapabilities (elicitation, tasks, roots, bogus)"}
}

// capabilityVariant describes one clientCapabilities configuration to test.
type capabilityVariant struct {
	class        string
	label        string
	capabilities map[string]any
}

// capabilityVariants returns the set of clientCapabilities configurations to test.
func (p *CapabilityEscalation) capabilityVariants() []capabilityVariant {
	return []capabilityVariant{
		{
			class: "capability-escalation",
			label: "elicitation (form + url)",
			capabilities: map[string]any{
				"elicitation": map[string]any{
					"form": map[string]any{},
					"url":  map[string]any{},
				},
			},
		},
		{
			class: "capability-escalation",
			label: "extensions/tasks",
			capabilities: map[string]any{
				"extensions": map[string]any{
					"io.modelcontextprotocol/tasks": map[string]any{},
				},
			},
		},
		{
			class: "capability-escalation",
			label: "roots (listChanged)",
			capabilities: map[string]any{
				"roots": map[string]any{
					"listChanged": true,
				},
			},
		},
		{
			class: "capability-all",
			label: "all capabilities declared",
			capabilities: map[string]any{
				"elicitation": map[string]any{
					"form": map[string]any{},
					"url":  map[string]any{},
				},
				"roots": map[string]any{
					"listChanged": true,
				},
				"sampling": map[string]any{},
				"extensions": map[string]any{
					"io.modelcontextprotocol/tasks": map[string]any{},
				},
			},
		},
		{
			class: "capability-bogus",
			label: "bogus admin/debug extensions",
			capabilities: map[string]any{
				"extensions": map[string]any{
					"io.modelcontextprotocol/admin": map[string]any{},
					"io.modelcontextprotocol/debug": map[string]any{},
				},
			},
		},
	}
}

// buildMeta constructs the _meta fields with the given clientCapabilities.
func (p *CapabilityEscalation) buildMeta(capabilities map[string]any) map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion": "2026-07-28",
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name":    "augustus-scan",
			"version": "1.0",
		},
		"io.modelcontextprotocol/clientCapabilities": capabilities,
	}
}

// Probe resolves the endpoint and runs the capability escalation sweep.
func (p *CapabilityEscalation) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint := p.resolveEndpoint(gen)
	if endpoint == "" {
		return nil, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.CapabilityEscalation: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("mcptransport.CapabilityEscalation: skipping non-HTTP transport", "endpoint", endpoint)
		return nil, nil
	}

	client, err := p.borrowHTTPClient(gen)
	if err != nil {
		return nil, err
	}
	var attempts []*attempt.Attempt

	// 1. Baseline: empty clientCapabilities.
	baselineMeta := p.buildMeta(map[string]any{})
	baselineTools, baselineResp, baselineErr := p.sendToolsList(ctx, client, endpoint, baselineMeta)
	baseAttempt := p.recordAttempt("baseline", "empty clientCapabilities baseline", baselineTools, baselineTools, baselineResp, baselineErr, false)
	attempts = append(attempts, baseAttempt)

	if baselineErr != nil {
		slog.Info("mcptransport.CapabilityEscalation: baseline failed; cannot compare variants",
			"endpoint", endpoint, "err", baselineErr)
		return attempts, nil
	}

	// 2. Variants.
	for _, v := range p.capabilityVariants() {
		variantMeta := p.buildMeta(v.capabilities)
		variantTools, variantResp, variantErr := p.sendToolsList(ctx, client, endpoint, variantMeta)
		a := p.recordAttempt(v.class, v.label, baselineTools, variantTools, variantResp, variantErr, true)
		attempts = append(attempts, a)
	}

	return attempts, nil
}

// sendToolsList sends a tools/list JSON-RPC request with the given _meta.
func (p *CapabilityEscalation) sendToolsList(ctx context.Context, client *http.Client, endpoint string, meta map[string]any) ([]string, string, error) {
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
func (p *CapabilityEscalation) recordAttempt(class, label string, baseline, variant []string, transcript string, err error, isVariant bool) *attempt.Attempt {
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

// resolveEndpoint returns the endpoint URL from probe config or generator.
func (p *CapabilityEscalation) resolveEndpoint(gen types.Generator) string {
	if p.endpointOverride != "" {
		return p.endpointOverride
	}
	if mcpEnd, ok := gen.(types.MCPEndpoint); ok {
		return mcpEnd.EndpointURL()
	}
	return ""
}

// borrowHTTPClient returns the generator's http.Client with this probe's timeout.
func (p *CapabilityEscalation) borrowHTTPClient(gen types.Generator) (*http.Client, error) {
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

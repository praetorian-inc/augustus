package mcptransport

import (
	"context"
	"fmt"
	"maps"
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

func (p *MetadataInjection) variants() []differentialVariant {
	base := p.baselineMeta()
	return []differentialVariant{
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
			meta:    maps.Clone(base),
			headers: map[string]string{"mcp-method": "resources/list"},
		},
		{
			class:   "header-mismatch",
			label:   "mcp-protocol-version: 2024-11-05 (body says 2026-07-28)",
			meta:    maps.Clone(base),
			headers: map[string]string{"mcp-protocol-version": "2024-11-05"},
		},
	}
}

// Probe resolves the endpoint and runs the metadata injection sweep.
func (p *MetadataInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	endpoint, client, err := initSweep(ctx, p.Name(), p.endpointOverride, p.timeout, gen)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, nil
	}
	return runDifferentialSweep(ctx, sweepParams{
		probeName:    p.Name(),
		detectorName: p.GetPrimaryDetector(),
		endpoint:     endpoint,
		client:       client,
		baselineMeta: p.baselineMeta(),
		variants:     p.variants(),
	}), nil
}

func withProtocolVersion(base map[string]any, version string) map[string]any {
	m := maps.Clone(base)
	m["io.modelcontextprotocol/protocolVersion"] = version
	return m
}

func withClientInfo(base map[string]any, name, version string) map[string]any {
	m := maps.Clone(base)
	m["io.modelcontextprotocol/clientInfo"] = map[string]any{
		"name":    name,
		"version": version,
	}
	return m
}

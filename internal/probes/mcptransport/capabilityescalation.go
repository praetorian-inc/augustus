package mcptransport

import (
	"context"
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
}

// NewCapabilityEscalation constructs the probe.
func NewCapabilityEscalation(cfg registry.Config) (probes.Prober, error) {
	return &CapabilityEscalation{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 10)) * time.Second,
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

func (p *CapabilityEscalation) capabilityVariants() []differentialVariant {
	return []differentialVariant{
		{
			class: "capability-escalation",
			label: "elicitation (form + url)",
			meta: p.buildMeta(map[string]any{
				"elicitation": map[string]any{
					"form": map[string]any{},
					"url":  map[string]any{},
				},
			}),
		},
		{
			class: "capability-escalation",
			label: "extensions/tasks",
			meta: p.buildMeta(map[string]any{
				"extensions": map[string]any{
					"io.modelcontextprotocol/tasks": map[string]any{},
				},
			}),
		},
		{
			class: "capability-escalation",
			label: "roots (listChanged)",
			meta: p.buildMeta(map[string]any{
				"roots": map[string]any{
					"listChanged": true,
				},
			}),
		},
		{
			class: "capability-all",
			label: "all capabilities declared",
			meta: p.buildMeta(map[string]any{
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
			}),
		},
		{
			class: "capability-bogus",
			label: "bogus admin/debug extensions",
			meta: p.buildMeta(map[string]any{
				"extensions": map[string]any{
					"io.modelcontextprotocol/admin": map[string]any{},
					"io.modelcontextprotocol/debug": map[string]any{},
				},
			}),
		},
	}
}

// Probe resolves the endpoint and runs the capability escalation sweep.
func (p *CapabilityEscalation) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
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
		baselineMeta: p.buildMeta(map[string]any{}),
		variants:     p.capabilityVariants(),
	}), nil
}

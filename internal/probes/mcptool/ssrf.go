package mcptool

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolargs"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.SSRF", NewSSRF)
}

var (
	_ types.ProbeMetadata     = (*SSRF)(nil)
	_ recon.ContextAwareProbe = (*SSRF)(nil)
)

// urlParamRE matches parameter names likely to accept a URL/host, so the probe
// targets plausible SSRF sinks precisely. Set ssrf_all_string_params to widen to
// every string parameter.
var urlParamRE = regexp.MustCompile(`(?i)(^|[_\- ])(url|uri|endpoint|host|hostname|target|webhook|callback|link|href|src|source|dest|destination|proxy|fetch|address|domain|site|server|request)($|[_\- ])`)

// SSRF tests a directly-invokable tool surface for server-side request forgery.
// It stands up a built-in out-of-band collector, injects a unique canary URL
// into each URL-like tool parameter, then waits for the target to call back —
// catching blind SSRF (callback with no returned content) as well as non-blind
// SSRF (the tool returns the fetched body, matched by reflection).
type SSRF struct {
	reconContext
	listen       string            // OOB collector bind address
	baseOverride string            // URL the target should use to reach the collector (optional)
	wait         time.Duration     // grace period for callbacks after sending
	allParams    bool              // inject into every string param, not just URL-like ones
	marker       string            // collector body marker (reflection signal)
	policy       toolpolicy.Policy // destructive-tool safety gate
	// args carries the operator\'s per-tool argument hints (tool_args /
	// tool_id_paths). Empty by default, leaving synthesized arguments unchanged.
	args toolargs.Builder
}

// NewSSRF constructs the probe. All OOB settings default so a localhost target
// works with zero config (ephemeral collector, base derived from its address).
func NewSSRF(cfg registry.Config) (probes.Prober, error) {
	return &SSRF{
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		allParams:    registry.GetBool(cfg, "ssrf_all_string_params", false),
		marker:       "AUGOOB" + mcpprobe.RandToken(),
		policy:       toolpolicy.New(cfg),
		args:         toolargs.New(cfg),
	}, nil
}

func (p *SSRF) Name() string { return "mcptool.SSRF" }

// hasProbeableParam reports whether this tool exposes a parameter this probe
// would actually inject into. Used to decide whether the tool is worth a
// discovery invocation at all — see the call site in Probe.
func (p *SSRF) hasProbeableParam(params []paramInfo) bool {
	for _, param := range params {
		if !isStringParam(param.typ) {
			continue
		}
		if p.allParams || urlParamRE.MatchString(param.name) {
			return true
		}
	}
	return false
}

var _ types.RiskDescriber = (*SSRF)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *SSRF) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool issues a network request to a URL taken from its arguments without restricting the destination (server-side request forgery).",
		Impact:         "A caller can direct outbound requests from the tool's host, including to internal services and cloud metadata endpoints (e.g. 169.254.169.254) that are otherwise unreachable.",
		Recommendation: "Allowlist request destinations by scheme, host, and port; reject private, link-local, and cloud-metadata addresses; re-resolve DNS after validation to defeat rebinding; disable redirects to unvetted hosts; and apply egress filtering on the tool host.",
		References:     "https://cwe.mitre.org/data/definitions/918.html\nhttps://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
		Taxonomies:     "- cwe: 918",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus injects out-of-band canary URLs into URL-like tool arguments. A blind SSRF is proven when the canary host records a callback originating from the tool's server; a non-blind SSRF is proven when the fetched content is reflected back in the tool response. Reaching an internal-only destination (for example the cloud metadata service at 169.254.169.254) demonstrates the impact.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.SSRF` probe against the affected endpoint via the `mcp.MCP` generator (`mode: list_tools`). Blind detection requires reachable out-of-band callback infrastructure; without it, only reflected (non-blind) SSRF is observable.",
	}
}

func (p *SSRF) Description() string {
	return "Injects out-of-band canary URLs into URL-like tool arguments and detects server-side request forgery via callback (blind) or reflected content (non-blind)"
}

func (p *SSRF) Goal() string {
	return "Determine whether any directly-invokable tool fetches attacker-controlled URLs (SSRF)"
}

func (p *SSRF) GetPrimaryDetector() string { return "mcptool.SSRF" }

func (p *SSRF) GetPrompts() []string {
	return []string{"out-of-band SSRF canary URL injected into URL-like parameters"}
}

// Probe discovers tools, injects canary URLs into URL-like string params, waits
// for out-of-band callbacks, and records the callback/reflection signals per
// attempt. Returns no attempts (no error) for non-ToolInvoker targets.
func (p *SSRF) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	// Invoking tools requires a live ToolInvoker; recon only supplies the
	// catalog, so the canary URLs must be sent to the real target. A
	// non-ToolInvoker target cannot be tested — fail loud rather than return a
	// clean-looking empty result (a silent false negative for a scanner).
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.SSRF: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Prefer shared reconnaissance; fall back to live enumeration.
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.SSRF: list tools: %w", err)
	}
	// Apply the safety gate before invoking anything (skips destructive tools
	// unless opted in).
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	col, err := mcpprobe.StartCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, err
	}
	defer col.Close()

	type pending struct {
		a     *attempt.Attempt
		token string
	}

	var (
		attempts []*attempt.Attempt
		pend     []pending
	)

	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := toolParams(tool)
		// Only worth a real invocation if this probe has something to send this
		// tool. Gated on the TOOL, not on the parameter needing candidates: the
		// uncandidated parameter is typically a discriminator that must be
		// satisfied to reach the URL sink, not the URL parameter itself.
		if p.hasProbeableParam(params) {
			params = discoverToolValues(ctx, inv, name, params)
		}
		for _, param := range params {
			if !isStringParam(param.typ) {
				continue
			}
			if !p.allParams && !urlParamRE.MatchString(param.name) {
				continue
			}
			// Same placement matrix as mcptool.Injection: the bare canary URL
			// always, plus one led by a value the target declares valid. A URL
			// argument can sit behind the same first-token allowlist a command
			// argument does, and a bare canary would be refused before the fetch.
			for _, prefix := range payloadPrefixes(param) {
				token := mcpprobe.RandToken()
				canaryURL := col.URL(token)
				payload := prefix + canaryURL

				a := attempt.New(payload)
				a.Probe = p.Name()
				a.Detector = p.GetPrimaryDetector()
				a.Metadata["mcptool.tool"] = name
				a.Metadata["mcptool.param"] = param.name
				// The OOB URL, not the payload: with a prefix the two differ, and
				// the collector is keyed on the URL.
				a.Metadata[attempt.MetadataKeySSRFOOBURL] = canaryURL

				reflected := false
				res, callErr := inv.CallTool(ctx, name, buildArgs(p.args, name, params, param.name, payload))
				if callErr != nil {
					a.SetError(callErr)
				} else {
					a.AddOutput(res.Text)
					reflected = strings.Contains(res.Text, p.marker)
					a.Complete()
				}
				a.Metadata[attempt.MetadataKeySSRFReflected] = reflected

				pend = append(pend, pending{a: a, token: token})
				attempts = append(attempts, a)
			}
		}
	}

	if len(attempts) == 0 {
		slog.Warn("mcptool.SSRF: no URL-like tool parameters found; set ssrf_all_string_params=true to test every string parameter", "tools", len(tools))
		return nil, nil
	}

	// Give the target time to make out-of-band callbacks, then record results.
	mcpprobe.WaitForCallbacks(ctx, p.wait)
	for _, item := range pend {
		hit := col.WasHit(item.token)
		item.a.Metadata[attempt.MetadataKeySSRFCallback] = hit
		// A canary URL the target actually fetched (callback fired) is a confirmed
		// finding even when the tool call itself then failed. Left as StatusError the
		// attempt is classified "error", not "vuln" — results.Verdict returns early on
		// an errored status and never reaches the score — which silently buries the
		// blind SSRF this collector exists to catch. That combination is not exotic:
		// a tool fetching a slow or unresponsive internal host times out AFTER the
		// outbound request has gone, which is the most common shape of blind SSRF.
		// Preserve the original error for the reviewer and revert to complete so the
		// callback score produces a VULN verdict. Mirrors injection.go, which already
		// reconciles its callbacks this way.
		if hit && item.a.Status == attempt.StatusError {
			if item.a.Error != "" {
				item.a.Metadata["mcptool.ssrf_oob_call_error"] = item.a.Error
			}
			item.a.Complete()
		}
	}
	return attempts, nil
}

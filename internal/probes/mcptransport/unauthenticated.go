package mcptransport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptransport.UnauthenticatedAccess", NewUnauthenticatedAccess)
}

var (
	_ types.ProbeMetadata = (*UnauthenticatedAccess)(nil)
	_ types.RiskDescriber = (*UnauthenticatedAccess)(nil)
)

// UnauthenticatedAccess tests whether an MCP HTTP endpoint's configured
// authentication boundary actually keeps an unauthenticated caller out.
//
// # The verdict is a differential
//
// The probe does NOT report "an anonymous session worked". Against a target the
// operator supplied no credentials for, that is trivially true and worthless: an
// open server and a server whose authentication layer never runs look identical
// on the wire. A probe firing on it would be a false-positive generator that
// discredits itself on its first engagement.
//
// What it reports instead is the differential: credentials WERE configured for
// this target, and an equivalent request carrying none of them succeeded anyway —
// the configured boundary is decorative. With no credentials configured the probe
// SKIPS with a stated reason. It never reports SAFE for a target it could not
// assess, because a silent false negative is the worst outcome a scanner can
// produce.
//
// # Two severity tiers
//
// Anonymous ENUMERATION discloses the target's whole attack surface and is
// serious. Anonymous INVOCATION proves the server will ACT for that caller and is
// the critical proof. They are scored differently. Enumeration deliberately
// carries the headline finding, so the probe never needs to mutate a customer's
// state to make its case, and the invocation proof is restricted to read-only
// tools that pass the internal/toolpolicy safety gate.
//
// # Reachability matters
//
// A publicly reachable server with a decorative boundary is critical. A loopback
// development server behaving identically is expected, and is reported
// inconclusive rather than vulnerable. This reuses the same host classification
// the sibling OriginValidation probe applies, inverted: there loopback is the
// exploitable case (browser DNS rebinding), here it is the benign one.
type UnauthenticatedAccess struct {
	endpointOverride string
	timeout          time.Duration
	policy           toolpolicy.Policy
}

// NewUnauthenticatedAccess constructs the probe. The endpoint is resolved from
// the target generator via types.MCPEndpoint; the "endpoint" config key overrides
// that. Proxy and TLS settings are inherited from the generator — configure them
// there, not here.
func NewUnauthenticatedAccess(cfg registry.Config) (probes.Prober, error) {
	return &UnauthenticatedAccess{
		endpointOverride: registry.GetString(cfg, "endpoint", ""),
		timeout:          time.Duration(registry.GetInt(cfg, "request_timeout", 30)) * time.Second,
		policy:           toolpolicy.New(cfg),
	}, nil
}

func (p *UnauthenticatedAccess) Name() string { return "mcptransport.UnauthenticatedAccess" }

// RiskInfo is the curated security write-up for this probe's finding.
func (p *UnauthenticatedAccess) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP HTTP/SSE endpoint serves requests that carry none of the credentials configured for it. A session established without any authentication material completed the initialize handshake, enumerated the server's tool catalog, and invoked a tool — so the authentication boundary the deployment appears to define is not enforced on the request path.",
		Impact:         "Anyone who can reach the endpoint URL can use the MCP server as though they held the operator's credentials: they can enumerate every tool, resource and prompt it exposes, learn the internal systems it fronts, and invoke its tools. The tool surface typically wraps privileged backends, so this collapses the entire trust boundary in front of them and grants an unauthenticated caller whatever authority the server holds.",
		Recommendation: "Authenticate every MCP request before dispatching it, including the initialize handshake and the catalog listing methods, and reject any request without a valid credential. Enforce this in middleware ahead of the MCP handler so no method can be reached before the check runs. Do not rely on network placement, an unguessable URL, or client-side configuration as the control. Where the deployment fronts multiple tenants, authorize each request against the caller's identity as well as authenticating it.",
		References:     "https://cwe.mitre.org/data/definitions/306.html\nhttps://cwe.mitre.org/data/definitions/862.html\nhttps://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/\nhttps://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
		Taxonomies:     "- cwe: 306\n- cwe: 862\n- owasp: MCP07",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"The finding is a differential, not a single observation. Augustus first confirms that credentials were configured for the target and that the operator's authenticated session can exercise it, establishing a control. It then opens a second MCP session over the same transport with the credential-injecting layer removed, so the request carries no authentication material of any kind. The finding is recorded only when that credential-free session succeeds where a configured boundary should have refused it.\n\n" +
			"Two tiers are reported. Enumerating the tool catalogue anonymously is the serious tier and needs no state change to prove. Invoking a tool anonymously is the critical tier, because it shows the server acts on an unauthenticated caller's instructions rather than merely describing itself; only tools the server annotates read-only, or whose names denote a read-only operation, are invoked.\n\n" +
			"Severity also depends on reachability. A publicly reachable or private-network endpoint is reported as a finding. A loopback endpoint is reported inconclusive, because a development server with no authentication is expected rather than defective.\n\n" +
			"When no credentials were configured for the target, the probe skips and states why: anonymous success proves nothing about a boundary that was never established, and reporting it would be a false positive.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptransport.UnauthenticatedAccess` probe against the affected endpoint via the `mcp.MCP` generator, with the same credential headers configured. The credential-free session completes the handshake and lists the tool catalogue that the configured credentials were supposed to gate.",
	}
}

func (p *UnauthenticatedAccess) Description() string {
	return "Tests whether an MCP HTTP/SSE endpoint enforces the credentials configured for it, by comparing the operator's authenticated session against an otherwise identical session carrying no credentials. Scores only the differential — credentials configured AND the anonymous path still succeeded — so a target with no credentials configured is skipped rather than reported. Anonymous enumeration and anonymous invocation are scored as separate severity tiers, and a loopback target is inconclusive rather than vulnerable."
}

func (p *UnauthenticatedAccess) Goal() string {
	return "Determine whether the authentication boundary configured for an MCP endpoint is actually enforced. Score = 1.0 when an anonymous session invoked a tool on a reachable target, EnumerationScore when it only enumerated the catalog, InconclusiveScore on loopback/unresolvable targets, and 0.0 when the target refused the anonymous session."
}

func (p *UnauthenticatedAccess) GetPrimaryDetector() string {
	return "mcptransport.UnauthenticatedAccess"
}

func (p *UnauthenticatedAccess) GetPrompts() []string {
	return []string{"MCP initialize + tools/list + read-only tools/call over a session carrying no credentials"}
}

// Probe runs the authenticated/anonymous differential.
//
// Every early return is a LOUD skip or an error, never a silent clean result: a
// target that cannot be assessed must not be reported as safe.
func (p *UnauthenticatedAccess) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	end, ok := gen.(types.MCPEndpoint)
	if !ok {
		return nil, fmt.Errorf("mcptransport.UnauthenticatedAccess: target %q exposes no HTTP endpoint surface; this probe requires an HTTP-based MCP generator such as mcp.MCP", gen.Name())
	}
	endpoint := p.endpointOverride
	if endpoint == "" {
		endpoint = end.EndpointURL()
	}
	if endpoint == "" {
		return nil, fmt.Errorf("mcptransport.UnauthenticatedAccess: target %q reports no endpoint URL; cannot assess unauthenticated access", gen.Name())
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("mcptransport.UnauthenticatedAccess: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		slog.Warn("mcptransport.UnauthenticatedAccess: skipping non-HTTP transport; the credential boundary this probe tests is an HTTP request-path property",
			"endpoint", endpoint, "scheme", u.Scheme)
		return nil, nil
	}

	// THE precondition. Without knowing whether the operator configured
	// credentials, anonymous success is uninterpretable.
	rep, ok := gen.(mcpprobe.CredentialReporter)
	if !ok {
		slog.Warn("mcptransport.UnauthenticatedAccess: skipping — target cannot report whether credentials were configured, so an anonymous success would be uninterpretable (an open server and a server whose auth layer never runs are indistinguishable). This is NOT a clean result.",
			"target", gen.Name(), "endpoint", endpoint)
		return nil, nil
	}
	credHeaders := rep.ConfiguredCredentialHeaders()
	if len(credHeaders) == 0 {
		slog.Warn("mcptransport.UnauthenticatedAccess: skipping — no credentials are configured for this target, so there is no authentication boundary to test. Anonymous access will trivially succeed and proves nothing. Configure the target's credentials (e.g. headers: {Authorization: 'Bearer $KEY'} with api_key) to assess whether they are actually enforced. This is NOT a clean result.",
			"target", gen.Name(), "endpoint", endpoint)
		return nil, nil
	}

	// The authenticated control needs a live tool surface to exercise.
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptransport.UnauthenticatedAccess: target %q does not support direct tool invocation, so no authenticated control can be established; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Classify reachability BEFORE sending anything: a loopback development server
	// with no auth is expected, a public one is critical.
	targetClass := classifyTargetHost(ctx, u.Host)
	slog.Info("mcptransport.UnauthenticatedAccess: target classified",
		"host", u.Host, "class", string(targetClass), "credential_headers", strings.Join(credHeaders, ","))

	// --- A. Authenticated control -------------------------------------------
	// Establishes that the target is reachable and answers the operator. Without
	// it an anonymous "success" is not trustworthy evidence.
	authTools, authErr := inv.ListTools(ctx)
	// A truncated catalog still proves the authenticated session works, which is
	// all this control asserts.
	authOK := len(authTools) > 0 && (authErr == nil || errors.Is(authErr, types.ErrCatalogTruncated))

	stamp := func(a *attempt.Attempt, class string, anonOK bool) *attempt.Attempt {
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()
		a.Metadata[mcpprobe.MetaAuthClass] = class
		a.Metadata[mcpprobe.MetaAuthTargetClass] = string(targetClass)
		a.Metadata[mcpprobe.MetaAuthCredentialsConfigured] = true
		a.Metadata[mcpprobe.MetaAuthCredentialHeaders] = strings.Join(credHeaders, ",")
		a.Metadata[mcpprobe.MetaAuthAuthenticatedSucceeded] = authOK
		a.Metadata[mcpprobe.MetaAuthAnonymousSucceeded] = anonOK
		return a
	}

	var attempts []*attempt.Attempt

	base := attempt.New(fmt.Sprintf("authenticated control: tools/list with configured credentials (%s)", strings.Join(credHeaders, ", ")))
	if authErr != nil && !authOK {
		base.SetError(authErr)
	} else {
		base.AddOutput(fmt.Sprintf("authenticated tools/list returned %d tool(s)", len(authTools)))
		base.Complete()
	}
	attempts = append(attempts, stamp(base, mcpprobe.AuthClassAuthBaseline, false))

	if !authOK {
		slog.Warn("mcptransport.UnauthenticatedAccess: the authenticated control failed; anonymous results will be reported inconclusive rather than as a confident verdict",
			"endpoint", endpoint, "error", authErr)
	}

	// --- B. Anonymous enumeration -------------------------------------------
	sess, connErr := mcpprobe.ConnectAnonymous(ctx, end, p.timeout)
	enum := attempt.New("anonymous session: initialize + tools/list carrying no credentials")
	if connErr != nil {
		// The target refused the credential-free session. That is the SAFE signal,
		// and it is recorded as evidence rather than dropped — "the server refused
		// us" and "we never asked" must stay distinguishable in the report.
		enum.AddOutput("target refused the credential-free session: " + connErr.Error())
		enum.Complete()
		attempts = append(attempts, stamp(enum, mcpprobe.AuthClassAnonEnumeration, false))
		slog.Info("mcptransport.UnauthenticatedAccess: anonymous session refused; the configured boundary is enforced at the transport",
			"endpoint", endpoint, "error", connErr)
		return attempts, nil
	}
	defer sess.Close()

	anonTools, listErr := sess.ListTools(ctx)
	anonEnumOK := listErr == nil && len(anonTools) > 0
	if anonEnumOK {
		enum.AddOutput(fmt.Sprintf("anonymous tools/list returned %d tool(s): %s", len(anonTools), toolNames(anonTools)))
	} else if listErr != nil {
		enum.AddOutput("anonymous session established but tools/list was refused: " + listErr.Error())
	} else {
		enum.AddOutput("anonymous session established; tools/list returned an empty catalog")
	}
	enum.Complete()
	attempts = append(attempts, stamp(enum, mcpprobe.AuthClassAnonEnumeration, anonEnumOK))

	if !anonEnumOK {
		return attempts, nil
	}

	// --- C. Anonymous invocation -------------------------------------------
	// The critical proof: the server ACTS for an unauthenticated caller. Only
	// read-only, policy-permitted tools are eligible; enumeration above already
	// carries the headline finding, so nothing here needs to change target state.
	tool := p.pickInvocationTool(anonTools)
	if tool == nil {
		slog.Warn("mcptransport.UnauthenticatedAccess: no read-only tool available for the anonymous invocation proof; reporting the enumeration finding only. Set allow_destructive=true (or tool_allowlist) to widen it — but only against infrastructure where a state change is acceptable.",
			"endpoint", endpoint, "tools", len(anonTools))
		return attempts, nil
	}

	name, _ := tool["name"].(string)
	args := mcpprobe.BenignArgs(mcpprobe.ToolParams(tool), nil)
	call := attempt.New(fmt.Sprintf("anonymous session: tools/call %q carrying no credentials", name))
	call.Metadata[mcpprobe.MetaAuthTool] = name

	res, callErr := sess.CallTool(ctx, name, args)
	invOK := false
	switch {
	case callErr != nil:
		// A transport/protocol failure is not a denial we can interpret.
		call.AddOutput("anonymous tools/call failed: " + callErr.Error())
		call.Complete()
	case res.IsError:
		// The tool ran but reported an application error — commonly the server's
		// own authorization refusal. Not a confirmed invocation.
		call.AddOutput("anonymous tools/call returned a tool-level error: " + res.Text)
		call.Complete()
	default:
		invOK = true
		call.AddOutput(res.Text)
		call.Complete()
	}
	attempts = append(attempts, stamp(call, mcpprobe.AuthClassAnonInvocation, invOK))

	return attempts, nil
}

// pickInvocationTool chooses the tool for the invocation proof: the first that is
// both permitted by the operator's safety policy and read-only.
//
// Returns nil when nothing qualifies, which is a reported skip rather than a
// fallback to a riskier tool.
func (p *UnauthenticatedAccess) pickInvocationTool(tools []map[string]any) map[string]any {
	permitted := p.policy.Filter(p.Name(), tools)
	for _, tm := range permitted {
		if mcpprobe.IsReadOnlyTool(tm) {
			return tm
		}
	}
	return nil
}

// toolNames renders a compact, bounded tool-name list for the evidence. Bounded
// because a large catalog would otherwise be stored in full in every report.
func toolNames(tools []map[string]any) string {
	const limit = 20
	names := make([]string, 0, len(tools))
	for i, tm := range tools {
		if i == limit {
			names = append(names, fmt.Sprintf("…(+%d more)", len(tools)-limit))
			break
		}
		if n, _ := tm["name"].(string); n != "" {
			names = append(names, n)
		}
	}
	return strings.Join(names, ", ")
}

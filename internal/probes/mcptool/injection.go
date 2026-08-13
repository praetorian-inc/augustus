package mcptool

import (
	"context"
	"fmt"
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
	probes.Register("mcptool.Injection", NewInjection)
}

// Compile-time assertions: Injection exposes probe metadata and opts in to
// shared reconnaissance.
var (
	_ types.ProbeMetadata     = (*Injection)(nil)
	_ recon.ContextAwareProbe = (*Injection)(nil)
)

// Injection tests a directly-invokable tool surface for code / command /
// template injection. It sends two complementary payload families into every
// string parameter of every discovered tool:
//
//   - In-band computed-arithmetic canaries (bare eval, SSTI, shell arithmetic):
//     a tool that evaluates a payload returns the product (the marker), which
//     never appears in the payload text — so a tool that merely echoes input
//     cannot trigger a false positive.
//   - Out-of-band OS-command payloads (OWASP MCP05): shell-metacharacter payloads
//     that fetch a unique canary URL from a built-in collector. A tool that shells
//     out triggers a callback, catching BLIND command injection (nothing returned
//     to the client) as well as the non-blind case (the fetched body is reflected).
//
// The target must implement types.ToolInvoker; other targets are skipped.
type Injection struct {
	reconContext
	canary mcpprobe.Canary
	policy toolpolicy.Policy
	// args carries the operator\'s per-tool argument hints (tool_args /
	// tool_id_paths). Empty by default, leaving synthesized arguments unchanged.
	args         toolargs.Builder
	listen       string        // OOB collector bind address
	baseOverride string        // URL the target should use to reach the collector (optional)
	wait         time.Duration // grace period for callbacks after sending
	marker       string        // collector body (served on every hit; detection is by callback, not reflection)
}

// NewInjection constructs the probe with a fresh canary, the tool-safety policy
// parsed from config (allow_destructive, tool_allowlist, tool_denylist), and the
// out-of-band collector settings (all defaulted so a localhost target works with
// zero config).
func NewInjection(cfg registry.Config) (probes.Prober, error) {
	return &Injection{
		canary:       mcpprobe.NewCanary(),
		policy:       toolpolicy.New(cfg),
		args:         toolargs.New(cfg),
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		marker:       "AUGOOB" + mcpprobe.RandToken(),
	}, nil
}

func (p *Injection) Name() string { return "mcptool.Injection" }

var _ types.RiskDescriber = (*Injection)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *Injection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool passes attacker-controlled arguments to a code, command, or template evaluation sink instead of treating them as data.",
		Impact:         "A caller who can invoke the tool can run code, OS commands, or template expressions in the tool's process, bounded by that process's privileges.",
		Recommendation: "Don't pass tool arguments to eval/exec, a shell, or a template engine. Parse them with a restricted parser (e.g. an arithmetic-only grammar or ast.literal_eval), validate against an allowlist, and run tools with least privilege.",
		References:     "https://cwe.mitre.org/data/definitions/94.html\nhttps://cwe.mitre.org/data/definitions/95.html\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 94\n- cwe: 95\n- cwe: 78",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus enumerates the directly-invokable tools and injects a unique computed-arithmetic canary — a product of two random operands — into each string argument. Two independent signals confirm a sink:\n\n" +
			"- In-band: the tool returns the *evaluated product* rather than echoing the literal expression, showing the argument reached a code/command/template evaluation sink. The product is unguessable, so the match itself is not chance — but evaluation is only a finding for an argument not meant to be executed (a tool whose declared purpose is arithmetic evaluates legitimately). Judge the sink against the argument's intended role.\n" +
			"- Out-of-band: a shell-command payload triggers a callback to the augustus out-of-band host, proving OS-command execution independently of what the tool returns in-band.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.Injection` probe against the affected endpoint via the `mcp.MCP` generator (`mode: list_tools`). An in-band finding echoes the injected canary's product in the response; a blind finding is confirmed by the out-of-band callback rather than the response — so confirm against the recorded proof (the canary echo and/or the OOB hit), not the response text alone.",
	}
}

func (p *Injection) Description() string {
	return "Injects computed canary and out-of-band shell-command payloads into tool arguments to detect code/command/template injection sinks (including blind OS command injection) in directly-invokable tools"
}

func (p *Injection) Goal() string {
	return "Determine whether any directly-invokable tool evaluates or executes attacker-controlled arguments (RCE/SSTI/eval-class and OS command injection)"
}

func (p *Injection) GetPrimaryDetector() string { return "mcptool.Injection" }

func (p *Injection) GetPrompts() []string {
	out := append([]string(nil), p.canary.Payloads...)
	for _, f := range mcpprobe.OOBCmdFormats {
		out = append(out, fmt.Sprintf(f, "<oob-canary-url>"))
	}
	return out
}

// Probe discovers the target's tools and injects both payload families into each
// string parameter. Returns an error (not a clean empty result) when the target
// has no directly-invokable tool surface, so a non-tool target reads as
// unsupported rather than as a silent "no injection sinks".
func (p *Injection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	// Invoking tools requires a live ToolInvoker; recon only supplies the
	// catalog, so the payloads must be sent to the real target. A non-ToolInvoker
	// target cannot be tested by this probe — fail loud rather than return a
	// clean-looking empty result (a silent false negative for a scanner).
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.Injection: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Prefer shared reconnaissance; fall back to live enumeration.
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.Injection: list tools: %w", err)
	}
	// Apply the safety gate before invoking anything (skips destructive tools
	// unless opted in). A target that genuinely advertises no testable tools is a
	// legitimate empty result, not an error.
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	// The collector receives out-of-band callbacks from blind command-injection
	// sinks. Kept alive until after the callback grace period below.
	col, err := mcpprobe.StartCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, fmt.Errorf("mcptool.Injection: start OOB collector: %w", err)
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

sending:
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := toolParams(tool)
		params = discoverToolValues(ctx, inv, name, params)
		for _, param := range params {
			if !isStringParam(param.typ) {
				continue
			}
			// In-band computed-canary payloads (eval / SSTI / shell arithmetic).
			for _, payload := range p.canary.Payloads {
				for _, variant := range payloadVariants(param, payload) {
					// Stop issuing new calls the moment the context is done; the attempts
					// already sent are still recorded and their callbacks reconciled below.
					// Checked per-call (not per-param) so cancellation doesn't emit a burst
					// of immediately-erroring attempts for the rest of the param's payloads.
					if ctx.Err() != nil {
						break sending
					}
					attempts = append(attempts, p.callOne(ctx, inv, name, param.name, params, variant))
				}
			}
			// Out-of-band OS-command payloads (blind + non-blind command injection).
			for _, f := range mcpprobe.OOBCmdFormats {
				for _, prefix := range payloadPrefixes(param) {
					if ctx.Err() != nil {
						break sending
					}
					token := mcpprobe.RandToken()
					proofURL := mcpprobe.ShellProofURL(col.URL(token), token)
					a := p.callOOB(ctx, inv, name, param.name, params, prefix, f, proofURL)
					pend = append(pend, pending{a: a, token: token})
					attempts = append(attempts, a)
				}
			}
		}
	}

	// Give the target time to make out-of-band callbacks, then reconcile each
	// out-of-band attempt with what the collector saw.
	if len(pend) > 0 {
		mcpprobe.WaitForCallbacks(ctx, p.wait)
		for _, item := range pend {
			hit := col.WasHit(item.token)
			item.a.Metadata[attempt.MetadataKeyInjectionOOBCallback] = hit
			// A payload that executed (callback fired) but then hung or errored the
			// tool call is still a confirmed finding. Left as StatusError it would be
			// classified "error", not "vuln" (results.Verdict maps StatusError ->
			// error regardless of score), silently burying a blind RCE. Preserve the
			// original error for the reviewer and revert to complete so the callback
			// score produces a VULN verdict.
			if hit && item.a.Status == attempt.StatusError {
				if item.a.Error != "" {
					item.a.Metadata["mcptool.injection_oob_call_error"] = item.a.Error
				}
				item.a.Complete()
			}
		}
	}
	return attempts, nil
}

// callOne invokes a single (tool, param, payload) with an in-band computed canary
// and records the attempt.
func (p *Injection) callOne(ctx context.Context, inv types.ToolInvoker, tool, param string, params []paramInfo, payload string) *attempt.Attempt {
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyInjectionCanaries] = []string{p.canary.Marker}
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = param

	res, err := inv.CallTool(ctx, tool, buildArgs(p.args, tool, params, param, payload))
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}

// callOOB invokes a single (tool, param) with a shell-command-injection payload
// that fetches the collector's (shell-proof) canary URL, and records the attempt.
//
// Detection is by out-of-band callback ONLY — deliberately not by reflecting the
// collector body. The collector answers every /oob/<token> hit with the same
// marker, so a tool that merely extracts and fetches the URL from the argument
// text (an SSRF / link-preview sink, not a command sink) would get that marker
// back and be misclassified as command injection. The callback path avoids this:
// the URL's token carries a shell-proof marker (see mcpprobe.ShellProofURL) that only a
// real shell resolves to the tracked token, and the callback catches BOTH the
// blind case (nothing returned) and the non-blind case (a shell ran curl and the
// callback still fired), so dropping reflection loses no true positives.
func (p *Injection) callOOB(ctx context.Context, inv types.ToolInvoker, tool, param string, params []paramInfo, prefix, format, canaryURL string) *attempt.Attempt {
	payload := prefix + fmt.Sprintf(format, canaryURL)

	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyInjectionOOBURL] = canaryURL
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = param

	res, err := inv.CallTool(ctx, tool, buildArgs(p.args, tool, params, param, payload))
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}

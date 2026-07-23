package mcptool

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.ResponseLeak", NewResponseLeak)
}

// maxResponseBytes bounds how much of each tool response (Text and raw) is stored
// per output. 10 MiB is far above where a real leaked credential appears in a
// tool response, so it avoids the false-negative a small (1 MiB) cap caused —
// where a secret past the boundary was hidden before scoring — while still
// bounding report memory. It is deliberately larger than the previously-removed
// 1 MiB cap for exactly that reason.
const maxResponseBytes = 10 << 20 // 10 MiB

// truncateResponse caps s to maxResponseBytes, appending a marker when it cuts so
// a truncated output is distinguishable from one that happened to end there.
func truncateResponse(s string) string {
	if len(s) <= maxResponseBytes {
		return s
	}
	return s[:maxResponseBytes] + "…[truncated]"
}

// truncateResponseBytes caps a raw byte payload to maxResponseBytes and only then
// converts it to a string. Truncating before the []byte→string conversion avoids
// materializing the entire (possibly huge/hostile) raw payload as a string first,
// so the cap actually bounds the allocation rather than merely the stored output.
func truncateResponseBytes(b []byte) string {
	if len(b) <= maxResponseBytes {
		return string(b)
	}
	return string(b[:maxResponseBytes]) + "…[truncated]"
}

// Compile-time assertions: ResponseLeak exposes probe metadata and consumes prior
// reconnaissance (via the embedded reconContext).
var (
	_ types.ProbeMetadata     = (*ResponseLeak)(nil)
	_ recon.ContextAwareProbe = (*ResponseLeak)(nil)
)

// ResponseLeak tests a directly-invokable tool surface for secret exposure in
// tool RESPONSES (OWASP MCP01). It calls each discovered tool with inputs that
// tend to surface secrets — empty args (which elicit verbose required-parameter
// errors), benign required args (which reach normal output that may echo config
// or credentials), and a debug/verbose toggle when the tool exposes one — then
// scores every response with the mcpsecrets.Credential detector.
//
// The target must implement types.ToolInvoker; other targets fail loud rather
// than return a clean-looking empty result (a silent false negative).
//
// Any credential appearing in a tool response is reported, by design: this is an
// intended true-positive for OWASP MCP01. A tool whose legitimate purpose is to
// vend a secret (a secrets-vault read, get_env, an OAuth/token issuer) will
// therefore show as vulnerable. That is not a false positive — a directly
// invokable tool that returns live credentials is precisely the exposure this
// probe exists to surface. Operators who accept a specific secret-vending tool
// exclude it with the existing tool_denylist config key, which stops the probe
// invoking it at all (no attempt, no finding).
//
// SIDE EFFECTS: this probe INVOKES real tools with benign arguments (empty args,
// benign required-parameter values, and a debug/verbose toggle when present).
// The destructive-tool safety gate only skips tools the SERVER self-annotates as
// destructive (MCPToolAnnotations.Destructive); a tool that is destructive but
// unannotated IS invoked. When scanning production targets, set tool_allowlist
// (or tool_denylist) to restrict which tools the probe may call and avoid
// unintended side effects.
type ResponseLeak struct {
	reconContext
	policy toolpolicy.Policy
}

// NewResponseLeak constructs the probe with the shared tool-safety policy parsed
// from config (allow_destructive, tool_allowlist, tool_denylist).
func NewResponseLeak(cfg registry.Config) (probes.Prober, error) {
	return &ResponseLeak{policy: toolpolicy.New(cfg)}, nil
}

func (p *ResponseLeak) Name() string { return "mcptool.ResponseLeak" }

var _ types.RiskDescriber = (*ResponseLeak)(nil)

// RiskInfo is the curated security write-up for this probe's finding.
func (p *ResponseLeak) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool returns credentials or secrets in its response — for example in verbose errors, debug output, or echoed configuration.",
		Impact:         "A caller can collect API keys, tokens, or connection strings the tool exposes and reuse them against the systems those credentials protect.",
		Recommendation: "Keep secrets out of tool output: return generic errors, disable debug/verbose responses in production, and redact credential-shaped values before returning configuration or diagnostics. Scope each tool's own credentials to least privilege so a leak is contained.",
		References:     "https://cwe.mitre.org/data/definitions/200.html\nhttps://cwe.mitre.org/data/definitions/209.html\nhttps://cwe.mitre.org/data/definitions/532.html\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 200\n- cwe: 209\n- cwe: 532",
	}
}

func (p *ResponseLeak) Description() string {
	return "Invokes each tool with inputs that surface secrets in the response (verbose errors, debug output, echoed config) and scores responses for exposed credentials"
}

func (p *ResponseLeak) Goal() string {
	return "Determine whether any directly-invokable tool exposes credentials or secrets in its response output (OWASP MCP01)"
}

func (p *ResponseLeak) GetPrimaryDetector() string { return "mcpsecrets.Credential" }

func (p *ResponseLeak) GetPrompts() []string { return nil }

// Probe discovers the target's tools and invokes each with secret-surfacing
// argument cases. Returns no attempts (and no error) when the target advertises
// no testable tool surface.
func (p *ResponseLeak) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("mcptool.ResponseLeak: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Prefer a prior MCP inventory gathered by the recon phase; only fall back to
	// a live ListTools when none is available. Invocation still needs the live
	// ToolInvoker asserted above (recon supplies the catalog, not the transport).
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.ResponseLeak: list tools: %w", err)
	}
	// Apply the safety gate before invoking anything (skips destructive tools
	// unless opted in).
	advertised := len(tools)
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		// A target that advertised no tools at all is a legitimate empty result.
		// But a target whose tools were ALL excluded by policy is NOT clean: emit
		// one informational attempt so the scan doesn't read as a clean pass.
		if advertised == 0 {
			return nil, nil
		}
		return []*attempt.Attempt{p.gatedAttempt(advertised)}, nil
	}

	var attempts []*attempt.Attempt
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := toolParams(tool)
		for _, c := range argCases(params) {
			if err := ctx.Err(); err != nil {
				return attempts, err
			}
			attempts = append(attempts, p.callOne(ctx, inv, name, c))
		}
	}
	return attempts, nil
}

// callOne invokes a single (tool, case) and records the attempt.
func (p *ResponseLeak) callOne(ctx context.Context, inv types.ToolInvoker, tool string, c argCase) *attempt.Attempt {
	a := attempt.New(fmt.Sprintf("tool=%s case=%s", tool, c.name))
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.case"] = c.name

	res, err := inv.CallTool(ctx, tool, c.args)
	if err != nil {
		a.SetError(err)
		return a
	}
	// Store the response bounded to the generous maxResponseBytes cap (see its
	// doc): far above where real leaked credentials appear, so it does not hide a
	// secret the way a small cap would, while still bounding report memory.
	a.AddOutput(truncateResponse(res.Text))
	// Score the structured/raw payload too: a credential may appear only in the
	// raw result and never in the assembled Text. Cap the raw bytes BEFORE the
	// string conversion so a huge raw payload cannot force an unbounded allocation,
	// and dedupe against the (equally capped) Text form.
	if len(res.Raw) > 0 {
		if raw := truncateResponseBytes(res.Raw); raw != truncateResponse(res.Text) {
			a.AddOutput(raw)
		}
	}
	a.Complete()
	return a
}

// gatedAttempt records a benign, non-vulnerable attempt noting that every tool
// the target advertised was excluded by policy (allow/deny-list or the
// destructive gate). No tool was invoked; the attempt exists so an all-gated
// scan is distinguishable from a genuinely clean one.
func (p *ResponseLeak) gatedAttempt(advertised int) *attempt.Attempt {
	a := attempt.New("all advertised tools excluded by policy")
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.gated"] = advertised
	a.AddOutput(fmt.Sprintf("all %d advertised tool(s) were excluded by policy; none were invoked", advertised))
	a.Complete()
	return a
}

// argCase is one set of arguments to invoke a tool with, named for the attempt
// metadata so a finding points at which input surfaced the secret.
type argCase struct {
	name string
	args map[string]any
}

// debugParams are parameter names that commonly toggle verbose/debug output,
// which tends to surface config and credentials in the response.
var debugParams = map[string]bool{"debug": true, "verbose": true, "trace": true}

// argCases builds the secret-surfacing argument cases for a tool: empty args (to
// elicit verbose required-parameter errors), benign required args, and — when the
// tool exposes a debug/verbose/trace parameter — a variant that sets it true.
//
// Cases with identical argument maps are deduped by their canonical form, so a
// tool with no required params (where "empty" and "required" are both {}) is
// invoked once per distinct argument set rather than twice.
func argCases(params []paramInfo) []argCase {
	// Sort params by name before deriving cases: toolParams builds the slice by
	// iterating a Go map (randomized order), so the debug/verbose/trace cases —
	// and thus the produced attempt order — would otherwise vary between runs.
	// Sort a copy so the caller's slice is left untouched.
	params = append([]paramInfo(nil), params...)
	sort.Slice(params, func(i, j int) bool { return params[i].name < params[j].name })

	all := []argCase{
		{name: "empty", args: map[string]any{}},
		{name: "required", args: requiredArgs(params)},
	}
	for _, param := range params {
		if debugParams[strings.ToLower(param.name)] {
			args := requiredArgs(params)
			args[param.name] = true
			all = append(all, argCase{name: "debug:" + param.name, args: args})
		}
	}

	seen := make(map[string]bool, len(all))
	cases := make([]argCase, 0, len(all))
	for _, c := range all {
		key := canonicalJSON(c.args)
		if seen[key] {
			continue
		}
		seen[key] = true
		cases = append(cases, c)
	}
	return cases
}

// requiredArgs fills every required parameter with a benign placeholder value so
// the call reaches normal tool output instead of failing argument validation.
func requiredArgs(params []paramInfo) map[string]any {
	args := map[string]any{}
	for _, p := range params {
		if p.required {
			args[p.name] = benignValue(p.typ)
		}
	}
	return args
}

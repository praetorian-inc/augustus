package toolsec

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.ResponseLeak", NewResponseLeak)
}

// maxResponseBytes caps how much of a single tool response (Text and raw
// payload, each) is stored on an attempt. A hostile or buggy MCP target could
// return an enormous response; truncating before AddOutput bounds report memory.
// The cap is far larger than any real credential, so detection on normal-size
// responses is unchanged.
const maxResponseBytes = 1 << 20 // 1 MiB

// capResponse truncates s to maxResponseBytes, appending a short marker so a
// truncated response is distinguishable from one that happens to end there.
func capResponse(s string) string {
	if len(s) > maxResponseBytes {
		return s[:maxResponseBytes] + "...[truncated]"
	}
	return s
}

// Compile-time assertion: ResponseLeak exposes probe metadata.
var _ types.ProbeMetadata = (*ResponseLeak)(nil)

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
	policy toolpolicy.Policy
}

// NewResponseLeak constructs the probe with the shared tool-safety policy parsed
// from config (allow_destructive, tool_allowlist, tool_denylist).
func NewResponseLeak(cfg registry.Config) (probes.Prober, error) {
	return &ResponseLeak{policy: toolpolicy.New(cfg)}, nil
}

func (p *ResponseLeak) Name() string { return "toolsec.ResponseLeak" }

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
		return nil, fmt.Errorf("toolsec.ResponseLeak: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	tools, err := inv.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("toolsec.ResponseLeak: list tools: %w", err)
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
	a.Metadata["toolsec.tool"] = tool
	a.Metadata["toolsec.case"] = c.name

	res, err := inv.CallTool(ctx, tool, c.args)
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(capResponse(res.Text))
	// Score the structured/raw payload too: a credential may appear only in the
	// raw result and never in the assembled Text.
	if len(res.Raw) > 0 && string(res.Raw) != res.Text {
		a.AddOutput(capResponse(string(res.Raw)))
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
	a.Metadata["toolsec.gated"] = advertised
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

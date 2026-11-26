package mcptool

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.UnframedRelay", NewUnframedRelay)
}

var (
	_ types.ProbeMetadata     = (*UnframedRelay)(nil)
	_ recon.ContextAwareProbe = (*UnframedRelay)(nil)
)

// UnframedRelay tests whether a directly-invokable MCP tool relays
// caller-supplied content back to the host model interpolated into
// server-authored prose, without escaping, delimiting, or labelling it.
//
// The finding is AUTHORITY CONFUSION: attacker content becomes
// indistinguishable from server content in the model's context. This is the
// channel that enables indirect prompt injection through tool responses
// (OWASP MCP06 / MCP10).
//
// The probe sends a structurally distinctive canary — NOT an injection
// payload — into each string parameter of each discovered tool and checks
// the response for four simultaneous conditions: verbatim echo, no escaping,
// no delimiter, and substantial server-authored text around the canary. All
// four together are the finding; any alone is not.
//
// This probe is completely separate from mcptool.Injection. That probe uses a
// computed-arithmetic canary whose marker never appears in the payload,
// specifically so an echoing tool cannot false-positive. This probe needs the
// opposite property (a marker that IS echoed), so it uses its own canary
// (mcpprobe.RelayCanary) and its own detector. Conflating them would
// reintroduce the false positive that design prevents.
type UnframedRelay struct {
	reconContext
	canary mcpprobe.RelayCanary
	policy toolpolicy.Policy
}

// NewUnframedRelay constructs the probe with a fresh relay canary and the
// shared tool-safety policy.
func NewUnframedRelay(cfg registry.Config) (probes.Prober, error) {
	probe := &UnframedRelay{
		canary: mcpprobe.NewRelayCanary(),
		policy: toolpolicy.New(cfg),
	}
	probe.configure(cfg)
	return probe, nil
}

func (p *UnframedRelay) Name() string { return "mcptool.UnframedRelay" }

var _ types.RiskDescriber = (*UnframedRelay)(nil)

func (p *UnframedRelay) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool relays caller-supplied content back to the host model interpolated into server-authored prose, without escaping, delimiting, or labelling the relayed content.",
		Impact:         "Attacker-controlled content inherits the authority of the server's own output in the model's context. A model consuming the response cannot distinguish what the server said from what the caller planted, enabling indirect prompt injection through the tool's own response channel.",
		Recommendation: "Frame all relayed content with a data boundary: return it in a named JSON field with a source label, inside a code fence, or with explicit delimiters and escaping. Never interpolate untrusted content into server-authored prose as though the server wrote it.",
		References:     "https://cwe.mitre.org/data/definitions/74.html\nhttps://cwe.mitre.org/data/definitions/116.html\nhttps://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies:     "- cwe: 74\n- cwe: 116",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus sends a structurally distinctive canary into each string parameter of each tool. " +
			"The canary is not an injection payload: it observes how the server handles relayed content, " +
			"it does not attempt to manipulate the model.\n\n" +
			"A finding requires ALL FOUR conditions simultaneously:\n\n" +
			"1. The canary appears verbatim in the response (echoed back unchanged).\n" +
			"2. The canary is unescaped: no HTML entity, backslash, or URL encoding was applied.\n" +
			"3. The canary is undelimited: not inside a JSON string value, code fence, quoted block, or HTML code/pre tag.\n" +
			"4. The canary is adjacent to server-authored text: the response contains substantial server prose around it, so there is authority to borrow. A bare echo with no surrounding text does not fire.\n\n" +
			"Any one condition alone is not a finding. This is a channel detection, not a demonstrated exploit: " +
			"it proves the relay path exists and content passes through unframed, but does not prove a model " +
			"acted on injected instructions.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the mcptool.UnframedRelay probe against the affected endpoint via the mcp.MCP generator " +
			"(mode: list_tools). The flagged tool's response contains the relay canary embedded in server prose without framing.",
	}
}

func (p *UnframedRelay) Description() string {
	return "Sends a structurally distinctive canary into tool arguments and checks whether the response relays it back interpolated into server-authored prose without escaping, delimiting, or labelling (authority confusion channel)"
}

func (p *UnframedRelay) Goal() string {
	return "Determine whether any directly-invokable tool relays caller-supplied content into its response without a data boundary, enabling authority confusion (OWASP MCP06/MCP10)"
}

func (p *UnframedRelay) GetPrimaryDetector() string { return "mcptool.UnframedRelay" }

func (p *UnframedRelay) GetPrompts() []string { return p.canary.Payloads }

// Probe discovers the target's tools and injects relay canary payloads into
// each string parameter. Returns an error (not a clean empty result) when the
// target has no directly-invokable tool surface.
func (p *UnframedRelay) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := p.invoker(gen)
	if !ok {
		return nil, fmt.Errorf("mcptool.UnframedRelay: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.UnframedRelay: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	var attempts []*attempt.Attempt
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		for _, ts := range toolSignatures(tool, p.valueChain(ctx, name)) {
			p.warnBroadRules(name, ts.sig.Params)
			ts = ts.withShape(p.shapeMode()).discoverValues(ctx, inv, name)
			for _, param := range ts.params {
				if !isStringParam(param.typ) {
					continue
				}
				for _, payload := range p.canary.Payloads {
					if ctx.Err() != nil {
						return attempts, nil
					}
					attempts = append(attempts, p.callOne(ctx, inv, name, param, ts, payload))
				}
			}
		}
	}
	return attempts, nil
}

func (p *UnframedRelay) callOne(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig, payload string) *attempt.Attempt {
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyRelayCanary] = p.canary.Marker
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = string(param.path)

	args := ts.args(param, payload)
	res, err := inv.CallTool(ctx, tool, args)
	if err != nil {
		ts.recordCallFailure(a, param, args, err)
		return a
	}
	if res.IsError {
		a.Metadata[attempt.MetadataKeyTargetRefused] = true
	}
	a.AddOutput(mcpprobe.TruncateResponse(res.Text))
	a.Complete()
	return a
}

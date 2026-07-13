package toolsec

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.Injection", NewInjection)
}

// Compile-time assertions: Injection exposes probe metadata and opts in to
// shared reconnaissance.
var (
	_ types.ProbeMetadata     = (*Injection)(nil)
	_ recon.ContextAwareProbe = (*Injection)(nil)
)

// Injection tests a directly-invokable tool surface for code / command /
// template injection. For every string parameter of every discovered tool it
// sends computed-arithmetic canary payloads; a tool that evaluates a payload
// returns the product (the marker), which never appears in the payload text — so
// a tool that merely echoes input cannot trigger a false positive.
//
// The target must implement types.ToolInvoker; other targets are skipped.
type Injection struct {
	reconContext
	canary canary
	policy toolPolicy
}

// NewInjection constructs the probe with a fresh canary and the tool-safety
// policy parsed from config (allow_destructive, tool_allowlist, tool_denylist).
func NewInjection(cfg registry.Config) (probes.Prober, error) {
	return &Injection{canary: newCanary(), policy: newToolPolicy(cfg)}, nil
}

func (p *Injection) Name() string { return "toolsec.Injection" }

func (p *Injection) Description() string {
	return "Injects computed canary payloads into tool arguments to detect code/command/template injection sinks in directly-invokable tools"
}

func (p *Injection) Goal() string {
	return "Determine whether any directly-invokable tool evaluates attacker-controlled arguments (RCE/SSTI/eval-class injection)"
}

func (p *Injection) GetPrimaryDetector() string { return "toolsec.Injection" }

func (p *Injection) GetPrompts() []string { return p.canary.payloads }

// Probe discovers the target's tools and injects canary payloads into each
// string parameter. Returns no attempts (and no error) when the target has no
// directly-invokable tool surface.
func (p *Injection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	// Invoking tools requires a live ToolInvoker; recon only supplies the
	// catalog, so the payloads must be sent to the real target. A non-ToolInvoker
	// target cannot be tested by this probe — fail loud rather than return a
	// clean-looking empty result (a silent false negative for a scanner).
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, fmt.Errorf("toolsec.Injection: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	// Prefer shared reconnaissance; fall back to live enumeration.
	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("toolsec.Injection: list tools: %w", err)
	}
	// Apply the safety gate before invoking anything (skips destructive tools
	// unless opted in). A target that genuinely advertises no testable tools is a
	// legitimate empty result, not an error.
	tools = p.policy.filterTools(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	var attempts []*attempt.Attempt
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		params := toolParams(tool)
		for _, param := range params {
			if !isStringParam(param.typ) {
				continue
			}
			for _, payload := range p.canary.payloads {
				attempts = append(attempts, p.callOne(ctx, inv, name, param.name, params, payload))
			}
		}
	}
	return attempts, nil
}

// callOne invokes a single (tool, param, payload) and records the attempt.
func (p *Injection) callOne(ctx context.Context, inv types.ToolInvoker, tool, param string, params []paramInfo, payload string) *attempt.Attempt {
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyInjectionCanaries] = []string{p.canary.marker}
	a.Metadata["toolsec.tool"] = tool
	a.Metadata["toolsec.param"] = param

	res, err := inv.CallTool(ctx, tool, benignArgs(params, param, payload))
	if err != nil {
		a.SetError(err)
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}

package toolsec

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("toolsec.Injection", NewInjection)
}

// Compile-time assertion that Injection exposes probe metadata.
var _ types.ProbeMetadata = (*Injection)(nil)

// Injection tests a directly-invokable tool surface for code / command /
// template injection. For every string parameter of every discovered tool it
// sends computed-arithmetic canary payloads; a tool that evaluates a payload
// returns the product (the marker), which never appears in the payload text — so
// a tool that merely echoes input cannot trigger a false positive.
//
// The target must implement types.ToolInvoker; other targets are skipped.
type Injection struct {
	canary canary
}

// NewInjection constructs the probe with a fresh canary.
func NewInjection(_ registry.Config) (probes.Prober, error) {
	return &Injection{canary: newCanary()}, nil
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
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, nil
	}

	tools, err := inv.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("toolsec.Injection: list tools: %w", err)
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

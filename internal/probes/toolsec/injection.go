package toolsec

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/augustus/internal/toolpolicy"
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
	canary       canary
	policy       toolpolicy.Policy
	listen       string        // OOB collector bind address
	baseOverride string        // URL the target should use to reach the collector (optional)
	wait         time.Duration // grace period for callbacks after sending
	marker       string        // collector body marker (non-blind reflection signal)
}

// NewInjection constructs the probe with a fresh canary, the tool-safety policy
// parsed from config (allow_destructive, tool_allowlist, tool_denylist), and the
// out-of-band collector settings (all defaulted so a localhost target works with
// zero config).
func NewInjection(cfg registry.Config) (probes.Prober, error) {
	return &Injection{
		canary:       newCanary(),
		policy:       toolpolicy.New(cfg),
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		marker:       "AUGOOB" + randToken(),
	}, nil
}

func (p *Injection) Name() string { return "toolsec.Injection" }

func (p *Injection) Description() string {
	return "Injects computed canary and out-of-band shell-command payloads into tool arguments to detect code/command/template injection sinks (including blind OS command injection) in directly-invokable tools"
}

func (p *Injection) Goal() string {
	return "Determine whether any directly-invokable tool evaluates or executes attacker-controlled arguments (RCE/SSTI/eval-class and OS command injection)"
}

func (p *Injection) GetPrimaryDetector() string { return "toolsec.Injection" }

func (p *Injection) GetPrompts() []string {
	out := append([]string(nil), p.canary.payloads...)
	for _, f := range oobCmdFormats {
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
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	// The collector receives out-of-band callbacks from blind command-injection
	// sinks. Kept alive until after the callback grace period below.
	col, err := startCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, fmt.Errorf("toolsec.Injection: start OOB collector: %w", err)
	}
	defer col.close()

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
		for _, param := range params {
			if !isStringParam(param.typ) {
				continue
			}
			// In-band computed-canary payloads (eval / SSTI / shell arithmetic).
			for _, payload := range p.canary.payloads {
				attempts = append(attempts, p.callOne(ctx, inv, name, param.name, params, payload))
			}
			// Out-of-band OS-command payloads (blind + reflected command injection).
			for _, f := range oobCmdFormats {
				token := randToken()
				a := p.callOOB(ctx, inv, name, param.name, params, f, col.url(token))
				pend = append(pend, pending{a: a, token: token})
				attempts = append(attempts, a)
			}
		}
	}

	// Give the target time to make out-of-band callbacks, then record per-attempt
	// whether its canary URL was fetched (blind command injection).
	if len(pend) > 0 {
		p.waitForCallbacks(ctx)
		for _, item := range pend {
			item.a.Metadata[attempt.MetadataKeyInjectionOOBCallback] = col.wasHit(item.token)
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

// callOOB invokes a single (tool, param) with a shell-command-injection payload
// that fetches the collector's canary URL, and records the attempt. The collector
// marker is stored as the injection canary so the detector's existing
// marker-reflection path catches non-blind command injection (the tool returned
// the fetched body); the blind case is caught by the OOB callback recorded after
// the wait.
func (p *Injection) callOOB(ctx context.Context, inv types.ToolInvoker, tool, param string, params []paramInfo, format, canaryURL string) *attempt.Attempt {
	payload := fmt.Sprintf(format, canaryURL)

	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyInjectionCanaries] = []string{p.marker}
	a.Metadata[attempt.MetadataKeyInjectionOOBURL] = canaryURL
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

// waitForCallbacks sleeps for the grace period, honoring context cancellation.
func (p *Injection) waitForCallbacks(ctx context.Context) {
	if p.wait <= 0 {
		return
	}
	t := time.NewTimer(p.wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

package mcpprimitive

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcpprimitive.PromptInjection", NewPromptInjection)
}

var (
	_ types.ProbeMetadata           = (*PromptInjection)(nil)
	_ types.ProbeSecondaryDetectors = (*PromptInjection)(nil)
	_ types.RiskDescriber           = (*PromptInjection)(nil)
	_ recon.ContextAwareProbe       = (*PromptInjection)(nil)
)

// PromptInjection attacks the arguments of prompts/get. A prompt template is
// rendered SERVER-SIDE with caller-supplied argument values, which makes the
// renderer an injection sink in exactly the way a tool argument is:
//
//   - In-band computed-arithmetic canaries prove template/expression evaluation
//     (SSTI, eval). The canary's product never appears in the payload text, so a
//     server that interpolates the argument literally — the correct behaviour —
//     cannot produce a false positive; only one that EVALUATES it can.
//   - Out-of-band OS-command payloads prove the renderer shells out, catching the
//     blind case where the rendered prompt reveals nothing.
//
// Prompt templates that declare no arguments are still fetched once, unattacked,
// so the secondary content detector can score the template the server serves for
// smuggled model-directed instructions — the RADE half of this surface.
//
// Unlike tool arguments, MCP prompt arguments carry no JSON-schema type (the spec
// declares name/description/required only), so every argument is a candidate
// string sink and there is no type filter to apply.
type PromptInjection struct {
	reconContext
	canary       mcpprobe.Canary
	listen       string        // OOB collector bind address
	baseOverride string        // URL the target should use to reach the collector
	wait         time.Duration // grace period for callbacks after sending
	marker       string        // collector body marker
	maxTargets   int           // cap on prompt templates attacked
}

// NewPromptInjection constructs the probe with a fresh canary. Every setting
// defaults so a localhost target works with zero config.
func NewPromptInjection(cfg registry.Config) (probes.Prober, error) {
	return &PromptInjection{
		canary:       mcpprobe.NewCanary(),
		listen:       registry.GetString(cfg, "oob_listen", "127.0.0.1:0"),
		baseOverride: registry.GetString(cfg, "oob_base_url", ""),
		wait:         time.Duration(registry.GetInt(cfg, "oob_wait_seconds", 3)) * time.Second,
		marker:       "AUGOOB" + mcpprobe.RandToken(),
		maxTargets:   registry.GetInt(cfg, "prompt_max_targets", 25),
	}, nil
}

func (p *PromptInjection) Name() string { return "mcpprimitive.PromptInjection" }

func (p *PromptInjection) Description() string {
	return "Injects computed-arithmetic canaries and out-of-band shell-command payloads into MCP prompt-template arguments to detect server-side template evaluation (SSTI/eval) and OS-command execution in the prompt renderer, including the blind case"
}

func (p *PromptInjection) Goal() string {
	return "Determine whether an MCP server evaluates or executes caller-supplied prompt-template arguments when rendering a prompts/get response"
}

func (p *PromptInjection) GetPrimaryDetector() string { return "mcpprimitive.Injection" }

// GetSecondaryDetectors scores the RENDERED template for smuggled model-directed
// instructions, so a poisoned prompt template is reported alongside the sink
// verdict (OWASP MCP10).
func (p *PromptInjection) GetSecondaryDetectors() []types.SecondaryDetector {
	return []types.SecondaryDetector{{Name: "mcpprimitive.ContentInjection"}}
}

// GetPrompts returns the payload shapes. The arithmetic canaries carry per-run
// operands, so the command family is rendered with a placeholder host.
func (p *PromptInjection) GetPrompts() []string {
	out := append([]string(nil), p.canary.Payloads...)
	for _, f := range mcpprobe.OOBCmdFormats {
		out = append(out, fmt.Sprintf(f, "oob-canary-url"))
	}
	return out
}

// RiskInfo is the curated security write-up for this probe's finding.
func (p *PromptInjection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "An MCP server renders a prompt template by evaluating caller-supplied argument values instead of interpolating them as inert text, so a prompts/get request reaches a template-expression or command-execution sink in the server process.",
		Impact:         "A caller who can request a prompt executes template expressions — and, where the renderer shells out, operating-system commands — in the server process, bounded only by that process's privileges. Because the rendered prompt is placed directly into a host model's context, the same sink also lets a caller rewrite the instructions the model receives.",
		Recommendation: "Treat prompt arguments as data: interpolate them with a templating mode that escapes rather than evaluates, or substitute them by explicit string replacement. Never pass an argument value to eval, a shell, or a template engine's expression evaluator. Validate each argument against the narrowest acceptable pattern, and run the server with least privilege.",
		References:     "https://cwe.mitre.org/data/definitions/94.html\nhttps://cwe.mitre.org/data/definitions/1336.html\nhttps://cwe.mitre.org/data/definitions/78.html\nhttps://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
		Taxonomies:     "- cwe: 94\n- cwe: 1336\n- cwe: 78\n- cwe: 95",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus renders each advertised prompt template, injecting a unique computed-arithmetic canary — the product of two random operands — into one declared argument at a time while supplying benign values for the rest. Two independent oracles confirm a sink:\n\n" +
			"- In-band: the rendered prompt contains the evaluated product rather than the literal expression that was submitted. Correct behaviour is to interpolate the argument as inert text, so the product's presence shows the argument was evaluated. The product is unguessable, so the match is not chance, and a server that echoes the submitted value verbatim cannot produce it.\n" +
			"- Out-of-band: a shell-command payload triggers a callback to the augustus out-of-band host, proving the renderer executed an operating-system command independently of what the rendered prompt contains.\n\n" +
			"Templates that declare no arguments are fetched once without a payload, so the served template is still scored for instructions aimed at the host model. A server that rejects the render returns a protocol error, recorded as the denial signal rather than treated as a finding.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcpprimitive.PromptInjection` probe against the affected endpoint via the `mcp.MCP` generator. An in-band finding echoes the canary's product in the rendered prompt; a blind finding is confirmed by the recorded out-of-band callback rather than the rendered text, so confirm against the recorded proof and not the response alone. Blind detection requires out-of-band infrastructure the target can reach.",
	}
}

// Probe renders every advertised prompt template with adversarial arguments.
// A target that cannot read primitives is a hard error; a target that genuinely
// advertises no prompt templates is a legitimate empty result.
func (p *PromptInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	reader, ok := gen.(types.MCPPrimitiveReader)
	if !ok {
		return nil, fmt.Errorf("mcpprimitive.PromptInjection: target %q cannot read MCP primitives; this probe requires a primitive-reading generator such as mcp.MCP", gen.Name())
	}

	// Unlike resource URIs, prompt names and their argument lists cannot be
	// guessed — the catalog is the only source, so its absence is fatal here.
	invs, err := p.resolveInventories(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcpprimitive.PromptInjection: enumerate prompt catalog: %w", err)
	}
	prompts := collectPrompts(invs, p.maxTargets)
	if len(prompts) == 0 {
		slog.Warn("mcpprimitive.PromptInjection: target advertises no prompt templates; nothing to attack",
			"probe", p.Name())
		return nil, nil
	}

	col, err := mcpprobe.StartCollector(p.listen, p.baseOverride, p.marker)
	if err != nil {
		return nil, fmt.Errorf("mcpprimitive.PromptInjection: start OOB collector: %w", err)
	}
	defer col.Close()

	var (
		attempts []*attempt.Attempt
		pend     []*attempt.Attempt
	)
	tokenOf := make(map[*attempt.Attempt]string)

sending:
	for _, pr := range prompts {
		// A template with no arguments has no injection point, but the template the
		// server serves is still worth scoring for smuggled instructions.
		if len(pr.Arguments) == 0 {
			if ctx.Err() != nil {
				break sending
			}
			attempts = append(attempts, p.render(ctx, reader, pr.Name, "", classPromptContent, nil, "", ""))
			continue
		}

		for _, arg := range pr.Arguments {
			if arg.Name == "" {
				continue
			}
			// In-band computed-canary payloads (template evaluation / eval).
			for _, payload := range p.canary.Payloads {
				if ctx.Err() != nil {
					break sending
				}
				args := promptArgs(pr.Arguments, arg.Name, payload)
				attempts = append(attempts, p.render(ctx, reader, pr.Name, arg.Name, classPromptSSTI, args, payload, ""))
			}
			// Out-of-band OS-command payloads (blind + non-blind command injection).
			for _, f := range mcpprobe.OOBCmdFormats {
				if ctx.Err() != nil {
					break sending
				}
				token := mcpprobe.RandToken()
				canaryURL := mcpprobe.ShellProofURL(col.URL(token), token)
				payload := fmt.Sprintf(f, canaryURL)
				args := promptArgs(pr.Arguments, arg.Name, payload)
				a := p.render(ctx, reader, pr.Name, arg.Name, classPromptOOBCmd, args, payload, canaryURL)
				attempts = append(attempts, a)
				pend = append(pend, a)
				tokenOf[a] = token
			}
		}
	}

	if len(pend) > 0 {
		mcpprobe.WaitForCallbacks(ctx, p.wait)
		for _, a := range pend {
			a.Metadata[attempt.MetadataKeyPrimitiveOOBCallback] = col.WasHit(tokenOf[a])
		}
	}
	return attempts, nil
}

// render issues one prompts/get and records the attempt. As with resources, a
// protocol error is the server's denial signal rather than a probe failure, so it
// is preserved in metadata and the attempt completed — keeping a refusal visible
// instead of collapsing it into an error verdict.
func (p *PromptInjection) render(
	ctx context.Context,
	reader types.MCPPrimitiveReader,
	name, arg, class string,
	args map[string]string,
	payload, canaryURL string,
) *attempt.Attempt {
	prompt := payload
	if prompt == "" {
		prompt = "render prompt template " + name
	}
	a := attempt.New(prompt)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[attempt.MetadataKeyPrimitiveTarget] = name
	a.Metadata[attempt.MetadataKeyPrimitiveClass] = class
	if arg != "" {
		a.Metadata[attempt.MetadataKeyPrimitiveArg] = arg
	}
	if class == classPromptSSTI {
		a.Metadata[attempt.MetadataKeyPrimitiveCanaries] = []string{p.canary.Marker}
	}
	if canaryURL != "" {
		a.Metadata[attempt.MetadataKeyPrimitiveOOBURL] = canaryURL
	}

	res, err := reader.GetPrompt(ctx, name, args)
	if err != nil {
		a.Metadata[attempt.MetadataKeyPrimitiveCallError] = err.Error()
		a.AddOutput("")
		a.Complete()
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}

// collectPrompts flattens the prompt templates across inventories, deduplicating
// by name and stopping at cap. It warns when the cap truncates the set so a
// narrowed scan is never mistaken for a complete one.
func collectPrompts(invs []*types.MCPInventory, limit int) []types.MCPPrompt {
	var out []types.MCPPrompt
	seen := make(map[string]bool)
	truncated := false
	for _, inv := range invs {
		if inv == nil {
			continue
		}
		for _, pr := range inv.Prompts {
			if pr.Name == "" || seen[pr.Name] {
				continue
			}
			if len(out) >= limit {
				truncated = true
				break
			}
			seen[pr.Name] = true
			out = append(out, pr)
		}
	}
	if truncated {
		slog.Warn("mcpprimitive.PromptInjection: prompt-template cap reached; later catalog entries were not attacked",
			"cap", limit)
	}
	return out
}

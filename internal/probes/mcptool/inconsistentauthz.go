package mcptool

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.InconsistentAuthorization", NewInconsistentAuthorization)
}

var (
	_ types.ProbeMetadata     = (*InconsistentAuthorization)(nil)
	_ recon.ContextAwareProbe = (*InconsistentAuthorization)(nil)
	_ types.RiskDescriber     = (*InconsistentAuthorization)(nil)
)

// InconsistentAuthorization detects when two functionally-equivalent MCP tools
// on the same server enforce different privilege levels for the same caller and
// input. The looser tool is an authorization bypass for the stricter one.
//
// Two-layer pairing: (1) always-on deterministic near-name heuristics, (2)
// opt-in LLM semantic pairing from catalog descriptions. For each pair, the
// probe calls both tools with identical arguments and records the differential
// for the detector to score. The probe is a payload SENDER only — it renders
// no verdict.
type InconsistentAuthorization struct {
	reconContext
	policy       toolpolicy.Policy
	pairingJudge generators.Generator
}

func NewInconsistentAuthorization(cfg registry.Config) (probes.Prober, error) {
	p := &InconsistentAuthorization{}
	p.configure(cfg)
	p.policy = toolpolicy.New(cfg)

	if genType, ok := cfg["pairing_generator_type"].(string); ok && genType != "" {
		genCfg := make(registry.Config)
		if gc, ok := cfg["pairing_generator_config"].(map[string]any); ok {
			for k, v := range gc {
				genCfg[k] = v
			}
		}
		gen, err := generators.Create(genType, genCfg)
		if err != nil {
			return nil, fmt.Errorf("inconsistent-authz pairing generator: %w", err)
		}
		p.pairingJudge = gen
	}

	return p, nil
}

func (p *InconsistentAuthorization) Name() string { return "mcptool.InconsistentAuthorization" }

func (p *InconsistentAuthorization) Description() string {
	return "Detects inconsistent authorization between functionally-equivalent MCP tools — two tools fronting the same operation enforce different privilege levels"
}

func (p *InconsistentAuthorization) Goal() string {
	return "Determine whether two equivalent tools on the same server apply different authorization, allowing bypass via the looser entry point"
}

func (p *InconsistentAuthorization) GetPrimaryDetector() string {
	return "mcptool.InconsistentAuthorization"
}

func (p *InconsistentAuthorization) GetPrompts() []string {
	return []string{"identical arguments to two functionally-equivalent tools, comparing responses for authorization differential"}
}

func (p *InconsistentAuthorization) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description: "Two functionally-equivalent tools on the same MCP server enforce " +
			"different authorization levels for the same caller and input. An attacker " +
			"can bypass the stricter tool's access controls by calling the looser " +
			"equivalent, which returns privileged data the stricter tool withholds.",
		Impact: "Authorization bypass: an unprivileged caller obtains data or " +
			"performs actions that the server's own access controls on the stricter " +
			"tool are designed to prevent.",
		Recommendation: "Ensure all tools that front the same operation enforce " +
			"identical authorization checks. Consolidate duplicate tool implementations " +
			"behind a single authorization gate.",
		References: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
		Taxonomies: "- owasp-mcp: MCP02\n- owasp-mcp: MCP07\n- cwe: 862\n- cwe: 863\n- cwe: 1220",
		CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus identifies tool pairs that front the same operation (by name " +
			"similarity or LLM-assisted semantic analysis of descriptions), then calls " +
			"both with identical arguments under the same session. A materially different " +
			"response — one tool returning elevated privileges or sensitive data that the " +
			"other withholds — is an authorization inconsistency.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.InconsistentAuthorization` probe against the affected " +
			"endpoint via the `mcp.MCP` generator with the `recon.MCP` module enabled.",
	}
}

// Probe identifies functionally-equivalent tool pairs and calls both with
// identical arguments. It records the differential as attempt metadata for
// the detector to score.
func (p *InconsistentAuthorization) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	invoker, ok := p.invoker(gen)
	if !ok {
		return nil, fmt.Errorf("mcptool.InconsistentAuthorization: target does not implement ToolInvoker")
	}

	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, err
	}

	allowed := p.policy.Filter(p.Name(), tools)

	safe := make([]map[string]any, 0, len(allowed))
	for _, tm := range allowed {
		if mcpprobe.InvokesDestructiveOperation(tm) {
			name, _ := tm["name"].(string)
			slog.Debug("mcptool.InconsistentAuthorization: skipping destructive tool", "tool", name)
			continue
		}
		safe = append(safe, tm)
	}
	if len(safe) < 2 {
		return nil, nil
	}

	pairs := mcpprobe.NearNamePairs(safe)

	if p.pairingJudge != nil {
		semantic, serr := mcpprobe.SemanticPairs(ctx, safe, p.pairingJudge, pairs)
		if serr != nil {
			slog.Warn("mcptool.InconsistentAuthorization: semantic pairing failed; continuing with name-heuristic pairs only",
				"err", serr)
		} else if len(semantic) > 0 {
			pairs = append(pairs, semantic...)
		}
	}

	if len(pairs) == 0 {
		return nil, nil
	}

	toolMap := make(map[string]map[string]any, len(safe))
	for _, t := range safe {
		if name, _ := t["name"].(string); name != "" {
			toolMap[name] = t
		}
	}

	var attempts []*attempt.Attempt
	for _, pair := range pairs {
		toolA, okA := toolMap[pair.ToolA]
		toolB, okB := toolMap[pair.ToolB]
		if !okA || !okB {
			continue
		}
		if a := p.probePair(ctx, invoker, toolA, toolB, pair.Method); a != nil {
			attempts = append(attempts, a)
		}
	}

	return attempts, nil
}

func (p *InconsistentAuthorization) probePair(
	ctx context.Context,
	invoker types.ToolInvoker,
	toolA, toolB map[string]any,
	pairingMethod string,
) *attempt.Attempt {
	nameA, _ := toolA["name"].(string)
	nameB, _ := toolB["name"].(string)

	args := p.buildSharedArgs(ctx, toolA, toolB)
	if args == nil {
		slog.Debug("mcptool.InconsistentAuthorization: no shared arguments for pair; skipping",
			"tool_a", nameA, "tool_b", nameB)
		return nil
	}

	resA, errA := callToolOnce(ctx, invoker, nameA, args)
	if errA != nil {
		slog.Debug("mcptool.InconsistentAuthorization: tool A call failed",
			"tool", nameA, "err", errA)
		return nil
	}

	resB, errB := callToolOnce(ctx, invoker, nameB, args)
	if errB != nil {
		slog.Debug("mcptool.InconsistentAuthorization: tool B call failed",
			"tool", nameB, "err", errB)
		return nil
	}

	textA := mcpprobe.TruncateResponse(resA.Text)
	textB := mcpprobe.TruncateResponse(resB.Text)

	a := attempt.New(nameA + " vs " + nameB)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata[mcpprobe.MetaEquivToolA] = nameA
	a.Metadata[mcpprobe.MetaEquivToolB] = nameB
	a.Metadata[mcpprobe.MetaEquivResponseA] = cap2k(textA)
	a.Metadata[mcpprobe.MetaEquivResponseB] = cap2k(textB)
	a.Metadata[mcpprobe.MetaEquivPairingMethod] = pairingMethod

	argsJSON, _ := json.Marshal(args)
	a.Metadata[mcpprobe.MetaEquivArgs] = string(argsJSON)

	a.AddOutput(textA)
	a.AddOutput(textB)
	return a
}

func (p *InconsistentAuthorization) buildSharedArgs(ctx context.Context, toolA, toolB map[string]any) map[string]any {
	sigsA := mcpprobe.ToolSignatures(toolA)
	sigsB := mcpprobe.ToolSignatures(toolB)
	if len(sigsA) == 0 || len(sigsB) == 0 {
		return nil
	}

	bParamSet := make(map[string]bool)
	for _, param := range sigsB[0].Params {
		bParamSet[param.Path.Leaf()] = true
	}

	call := mcpprobe.BenignCall(sigsA[0])
	if call == nil {
		return nil
	}

	shared := make(map[string]any)
	for k, v := range call.Args() {
		if bParamSet[k] {
			shared[k] = v
		}
	}

	nameA, _ := toolA["name"].(string)
	chain := p.valueChain(ctx, nameA)
	for _, param := range sigsA[0].Params {
		leaf := param.Path.Leaf()
		if _, inShared := shared[leaf]; !inShared {
			continue
		}
		if v, _, ok := chain.Value(param); ok {
			shared[leaf] = v
		}
	}

	if len(shared) == 0 {
		return nil
	}
	return shared
}

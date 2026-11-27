package mcptool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/internal/toolsig"
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
		if !p.policy.AllowsDestructive() && mcpprobe.InvokesDestructiveOperation(tm) {
			name, _ := tm["name"].(string)
			slog.Warn("mcptool.InconsistentAuthorization: skipping destructive tool; set allow_destructive=true to include",
				"tool", name)
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
		if ctx.Err() != nil {
			break
		}
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

	resA, errA := callLeg(ctx, invoker, nameA, args)
	resB, errB := callLeg(ctx, invoker, nameB, args)

	// Both failed — nothing to compare.
	if errA != nil && errB != nil {
		slog.Debug("mcptool.InconsistentAuthorization: both tools errored; skipping",
			"tool_a", nameA, "tool_b", nameB)
		return nil
	}

	// A single-leg transport/timeout error is not an authz signal — only a
	// call refusal (JSON-RPC error from the server) is meaningful evidence.
	if errA != nil && !errors.Is(errA, types.ErrCallRefused) {
		slog.Debug("mcptool.InconsistentAuthorization: tool A transport error; skipping",
			"tool", nameA, "err", errA)
		return nil
	}
	if errB != nil && !errors.Is(errB, types.ErrCallRefused) {
		slog.Debug("mcptool.InconsistentAuthorization: tool B transport error; skipping",
			"tool", nameB, "err", errB)
		return nil
	}

	textA := ""
	if errA != nil {
		textA = fmt.Sprintf("[refused: %s]", errA)
	} else {
		textA = mcpprobe.TruncateResponse(resA.Text)
	}
	textB := ""
	if errB != nil {
		textB = fmt.Sprintf("[refused: %s]", errB)
	} else {
		textB = mcpprobe.TruncateResponse(resB.Text)
	}

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
	a.Complete()
	return a
}

// buildSharedArgs builds an argument map covering the INTERSECTION of both
// tools' parameter spaces. It uses Signature.Build with the probe's
// valueChain so nested and optional parameters are handled correctly.
//
// Parameters are matched by FULL PATH, not leaf name. Two params at different
// nesting levels (e.g. "filter.username" vs "username") have different wire
// shapes and are not interchangeable — sending one tool's shape to the other
// produces a schema-refusal, not an authorization signal.
//
// The pair is skipped when:
//   - either tool has no parseable signature,
//   - the intersection is empty,
//   - either tool has required parameters outside the intersection (calling
//     it without them produces a validation refusal, not an authz signal).
func (p *InconsistentAuthorization) buildSharedArgs(ctx context.Context, toolA, toolB map[string]any) map[string]any {
	sigsA := mcpprobe.ToolSignatures(toolA)
	sigsB := mcpprobe.ToolSignatures(toolB)
	if len(sigsA) == 0 || len(sigsB) == 0 {
		return nil
	}

	sigA, sigB := sigsA[0], sigsB[0]

	// Index both tools' params by full path.
	aByPath := make(map[toolsig.Path]toolsig.Param, len(sigA.Params))
	for _, pm := range sigA.Params {
		aByPath[pm.Path] = pm
	}
	bByPath := make(map[toolsig.Path]toolsig.Param, len(sigB.Params))
	for _, pm := range sigB.Params {
		bByPath[pm.Path] = pm
	}

	// Find shared paths — present in both tools with identical full path.
	sharedPaths := make(map[toolsig.Path]bool)
	for path := range aByPath {
		if _, ok := bByPath[path]; ok {
			sharedPaths[path] = true
		}
	}
	if len(sharedPaths) == 0 {
		return nil
	}

	// Skip pairs where either tool has required params outside the shared set.
	for _, pm := range sigA.Params {
		if pm.Required && !sharedPaths[pm.Path] {
			return nil
		}
	}
	for _, pm := range sigB.Params {
		if pm.Required && !sharedPaths[pm.Path] {
			return nil
		}
	}

	// Build a benign call from tool A's signature, which handles nested paths
	// and fills required params with harmless placeholders.
	call := mcpprobe.BenignCall(sigA)
	if call == nil {
		return nil
	}

	// Track which paths already have values (BenignCall fills A's required params).
	filled := make(map[toolsig.Path]bool, len(sigA.Params))
	for _, pm := range sigA.Params {
		if pm.Required {
			filled[pm.Path] = true
		}
	}

	// Overlay valueChain values for shared params (config > hooks > observed).
	nameA, _ := toolA["name"].(string)
	chain := p.valueChain(ctx, nameA)
	for _, pm := range sigA.Params {
		if !sharedPaths[pm.Path] {
			continue
		}
		if v, _, ok := chain.Value(pm); ok {
			call.Set(pm.Path, v)
			filled[pm.Path] = true
		}
	}

	// Fill shared params that are required in B but optional in A and not yet
	// filled by BenignCall or valueChain. Without this, tool B gets a call
	// missing a required param and fails schema validation — a false differential.
	// Use BenignCall(sigB) to get enum/const-aware placeholders rather than
	// naive type-based defaults.
	callB := mcpprobe.BenignCall(sigB)
	for _, pm := range sigB.Params {
		if !sharedPaths[pm.Path] || !pm.Required || filled[pm.Path] {
			continue
		}
		if callB != nil {
			if v, ok := callB.Get(pm.Path); ok {
				call.Set(pm.Path, v)
				continue
			}
		}
		call.Set(pm.Path, benignPlaceholder(pm.Type))
	}

	full := call.Args()

	// Keep only entries whose top-level key corresponds to a shared param.
	// For top-level params the key IS the path; for nested params (e.g.
	// "auth.username") the top-level key is the parent object ("auth").
	// Handle both "." and "[" separators for array-indexed paths.
	sharedTopKeys := make(map[string]bool)
	for _, pm := range sigA.Params {
		if sharedPaths[pm.Path] {
			top := string(pm.Path)
			if i := strings.IndexAny(top, ".["); i >= 0 {
				top = top[:i]
			}
			sharedTopKeys[top] = true
		}
	}

	shared := make(map[string]any, len(sharedTopKeys))
	for k, v := range full {
		if sharedTopKeys[k] {
			shared[k] = v
		}
	}

	if len(shared) == 0 {
		return nil
	}

	// Validate the shared args against both schemas. A type mismatch
	// (e.g. id:string vs id:integer) or an invalid enum value would
	// produce a schema-refusal, not an authorization signal.
	if err := sigA.Validate(shared); err != nil {
		slog.Debug("mcptool.InconsistentAuthorization: shared args fail tool A schema; skipping",
			"tool_a", nameA, "err", err)
		return nil
	}
	nameB, _ := toolB["name"].(string)
	if err := sigB.Validate(shared); err != nil {
		slog.Debug("mcptool.InconsistentAuthorization: shared args fail tool B schema; skipping",
			"tool_b", nameB, "err", err)
		return nil
	}

	return shared
}

// benignPlaceholder returns a harmless placeholder for a parameter type,
// mirroring mcpprobe.benignValue (which is unexported). Used to fill shared
// params that are optional in one tool but required in the other.
func benignPlaceholder(typ string) any {
	switch typ {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return "test"
	}
}

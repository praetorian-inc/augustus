package mcptool

import (
	"context"
	"log/slog"

	"github.com/praetorian-inc/augustus/internal/observed"
	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/internal/toolsig"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// DefaultIdentity labels the session a probe runs under when the operator names
// no other. Values observed in tool responses are partitioned by identity, so
// recon and the probes that follow it must agree on this label to share what the
// target handed out; both default to the same string so that they do.
const DefaultIdentity = "primary"

// reconContext is embedded by mcptool probes to consume shared reconnaissance.
// It provides the ContextAwareProbe opt-in, a tool-source resolver that prefers
// a prior MCP inventory over a second live enumeration, and the value chain used
// to fill arguments.
type reconContext struct {
	store    *recon.Store
	observed *observed.Store
	identity string
	rules    []toolsig.Rule
}

// SetContext implements recon.ContextAwareProbe. The scan runner calls it once,
// before Probe(), with the shared assessment state.
func (r *reconContext) SetContext(pc recon.ProbeContext) {
	r.store = pc.Recon
	r.observed = pc.Observed
}

// configure reads the value rules and identity label from a probe's own config.
func (r *reconContext) configure(cfg registry.Config) {
	r.rules = toolsig.RulesFromConfig(cfg)
	r.identity = registry.GetString(cfg, "identity_label", DefaultIdentity)
}

// invoker returns the target's tool interface with response recording attached,
// so that every value the target hands back becomes available to fill a later
// argument. Wrapping here rather than at each call site means no probe has to
// remember to do it, and forgetting cannot silently cost coverage.
func (r *reconContext) invoker(gen types.Generator) (types.ToolInvoker, bool) {
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, false
	}
	return observed.Wrap(inv, r.observed, r.identityOrDefault()), true
}

func (r *reconContext) identityOrDefault() string {
	if r.identity == "" {
		return DefaultIdentity
	}
	return r.identity
}

// valueChain is the ordered set of places an argument value may come from,
// consulted before the probe's own synthesised filler.
//
// Explicit beats inferred, which is why configuration comes first. An operator
// who writes a rule is making a statement about the target; a value scraped from
// a response is an inference about it. Ordering configuration below the scrape
// would leave no way to override a wrong inference at all, whereas an operator
// who wants the observed value simply writes no rule.
//
// Hook variables sit next because they are also operator-supplied, just fetched
// when the scan starts rather than written down. Observed values come last of
// the real sources: better than a placeholder, weaker than a statement.
func (r *reconContext) valueChain(ctx context.Context, tool string) toolsig.Chain {
	var c toolsig.Chain
	if len(r.rules) > 0 {
		c = append(c, toolsig.FromRules(tool, r.rules))
	}
	if vars := types.HookVarsFromContext(ctx); len(vars) > 0 {
		c = append(c, toolsig.FromHookVars(vars))
	}
	if r.observed != nil {
		c = append(c, r.observed.Source(r.identityOrDefault()))
	}
	return c
}

// warnBroadRules reports a rule matching an unusually large share of a tool's
// parameters. A rule keyed on a distinctive name is precise; one keyed on "id"
// will claim every identifier in the tool, and the difference is only visible
// once the parameters are known.
func (r *reconContext) warnBroadRules(tool string, params []toolsig.Param) {
	const threshold = 3
	for _, rule := range toolsig.BroadRules(tool, r.rules, params, threshold) {
		slog.Warn("mcptool: a configured value rule matches many parameters; narrow it with a path or tool selector if that is not intended",
			"tool", tool, "match_name", rule.Name, "match_path", rule.Path, "threshold", threshold)
	}
}

// resolveTools returns the target's tool surface as ListTools-shaped maps. It
// prefers tools described by a shared MCP inventory observation (gathered once
// by the recon phase) so probes need not re-enumerate; only when no such
// inventory is available does it fall back to a live ToolInvoker.ListTools call.
// A non-ToolInvoker target with no recon yields (nil, nil).
//
// An inventory is reused only when its TOOLS catalog was fully enumerated. A
// truncated tool catalog (see types.MCPInventory.Incomplete) is a lower bound on the
// surface, so reusing it would let a server that halted recon after a benign prefix
// have every probe score that prefix and report clean. Falling through to a live
// enumeration gives the target a fresh full walk, and that call fails closed if it
// truncates too — so an unscannable surface surfaces as an error, never as a pass.
//
// The check is per catalog rather than IsComplete(): these probes need only the tool
// surface, and discarding a complete tool catalog because an unrelated prompts or
// resources enumeration failed would force a redundant network walk that could then
// fail closed and abort probes that had everything they needed.
func (r *reconContext) resolveTools(ctx context.Context, gen types.Generator) ([]map[string]any, error) {
	if r.store != nil {
		var tools []map[string]any
		for _, inv := range mcpx.InventoriesFrom(r.store) {
			if !inv.IsCatalogComplete(types.MCPCatalogTools) {
				slog.Warn("mcptool: ignoring an inventory with an incomplete tools catalog; re-enumerating the tool surface",
					"incomplete_catalogs", inv.Incomplete, "tools_in_inventory", len(inv.Tools))
				continue
			}
			tools = append(tools, inv.ToolMaps()...)
		}
		if len(tools) > 0 {
			return tools, nil
		}
	}
	inv, ok := gen.(types.ToolInvoker)
	if !ok {
		return nil, nil
	}
	return inv.ListTools(ctx)
}

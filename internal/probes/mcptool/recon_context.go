package mcptool

import (
	"context"
	"log/slog"

	mcpx "github.com/praetorian-inc/augustus/internal/recon/mcp"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// reconContext is embedded by mcptool probes to consume shared reconnaissance.
// It provides the ContextAwareProbe opt-in plus a tool-source resolver that
// prefers a prior MCP inventory over a second live enumeration.
type reconContext struct {
	store *recon.Store
}

// SetContext implements recon.ContextAwareProbe. The scan runner calls it once,
// before Probe(), with the shared observation store.
func (r *reconContext) SetContext(pc recon.ProbeContext) { r.store = pc.Recon }

// resolveTools returns the target's tool surface as ListTools-shaped maps. It
// prefers tools described by a shared MCP inventory observation (gathered once
// by the recon phase) so probes need not re-enumerate; only when no such
// inventory is available does it fall back to a live ToolInvoker.ListTools call.
// A non-ToolInvoker target with no recon yields (nil, nil).
//
// Only a COMPLETE inventory is reused. An inventory whose catalog enumeration
// stopped early (see types.MCPInventory.Incomplete) is a lower bound on the tool
// surface, so reusing it would let a server that halted recon after a benign
// prefix have every probe score that prefix and report clean. Skipping to a live
// enumeration gives the target a fresh full walk, and that call fails closed if it
// truncates too — so an unscannable surface surfaces as an error, never as a pass.
func (r *reconContext) resolveTools(ctx context.Context, gen types.Generator) ([]map[string]any, error) {
	if r.store != nil {
		var tools []map[string]any
		for _, inv := range mcpx.InventoriesFrom(r.store) {
			if !inv.IsComplete() {
				slog.Warn("mcptool: ignoring an incomplete MCP inventory; re-enumerating the tool surface",
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

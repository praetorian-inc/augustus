package mcptool

import (
	"context"

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
func (r *reconContext) resolveTools(ctx context.Context, gen types.Generator) ([]map[string]any, error) {
	if r.store != nil {
		var tools []map[string]any
		for _, inv := range mcpx.InventoriesFrom(r.store) {
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

package mcp

import (
	"encoding/json"

	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// InventoriesFrom decodes every MCP inventory observation held by the store back
// into a typed *types.MCPInventory. It is the reader counterpart to the writer
// in (*MCP).Recon: both sides agree on ObservationTypeInventory and the payload
// schema, so this package remains the single source of truth for the
// mcp.inventory observation shape.
//
// Observations of other types, and observations whose payload fails to decode,
// are skipped. A nil store yields no inventories.
func InventoriesFrom(store *recon.Store) []*types.MCPInventory {
	if store == nil {
		return nil
	}
	var out []*types.MCPInventory
	for _, o := range store.Observations() {
		if o.Type != ObservationTypeInventory {
			continue
		}
		var inv types.MCPInventory
		if err := json.Unmarshal(o.Data, &inv); err != nil {
			continue
		}
		out = append(out, &inv)
	}
	return out
}

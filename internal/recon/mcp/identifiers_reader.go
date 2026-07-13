package mcp

import (
	"encoding/json"

	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// IdentifiersFrom decodes every mcp.identifiers observation held by the store
// back into a typed *types.MCPIdentifiers. It is the reader counterpart to the
// writer in (*MCPIdentifiers).Recon: both sides agree on
// ObservationTypeIdentifiers and the payload schema, so this package remains the
// single source of truth for the mcp.identifiers observation shape.
//
// Observations of other types, and observations whose payload fails to decode,
// are skipped. A nil store yields no identifiers.
func IdentifiersFrom(store *recon.Store) []*types.MCPIdentifiers {
	if store == nil {
		return nil
	}
	var out []*types.MCPIdentifiers
	for _, o := range store.Observations() {
		if o.Type != ObservationTypeIdentifiers {
			continue
		}
		var id types.MCPIdentifiers
		if err := json.Unmarshal(o.Data, &id); err != nil {
			continue
		}
		out = append(out, &id)
	}
	return out
}

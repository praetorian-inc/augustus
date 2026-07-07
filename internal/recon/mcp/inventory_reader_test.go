package mcp

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// InventoriesFrom is the reader counterpart to Recon()'s writer: it decodes
// every mcp.inventory observation in a store back into a typed inventory, and
// ignores observations of other types.
func TestInventoriesFrom(t *testing.T) {
	store := recon.NewStore()

	inv := types.MCPInventory{ServerName: "acme", Tools: []types.MCPTool{{Name: "echo"}}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store.Observe(output.Observation{Type: ObservationTypeInventory, Target: "acme", Data: data})
	store.Observe(output.Observation{Type: "some.other.kind", Data: json.RawMessage(`{"x":1}`)})

	got := InventoriesFrom(store)
	if len(got) != 1 {
		t.Fatalf("InventoriesFrom len = %d, want 1 (other types ignored)", len(got))
	}
	if got[0].ServerName != "acme" || len(got[0].Tools) != 1 || got[0].Tools[0].Name != "echo" {
		t.Errorf("decoded inventory wrong: %+v", got[0])
	}
}

// A nil store yields no inventories rather than panicking.
func TestInventoriesFrom_NilStore(t *testing.T) {
	if got := InventoriesFrom(nil); got != nil {
		t.Errorf("InventoriesFrom(nil) = %v, want nil", got)
	}
}

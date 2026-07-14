package mcp

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// IdentifiersFrom is the reader counterpart to the identifiers module's writer:
// it decodes every mcp.identifiers observation in a store back into a typed
// payload and ignores observations of other types.
func TestIdentifiersFrom(t *testing.T) {
	store := recon.NewStore()

	payload := types.MCPIdentifiers{
		Identity: "tenant-a",
		Objects: []types.MCPObjectRef{{
			Tool: "get_order", Param: "id", ID: "ord_1", Source: "list_orders",
		}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	store.Observe(output.Observation{Type: ObservationTypeIdentifiers, Target: "tenant-a", Data: data})
	store.Observe(output.Observation{Type: ObservationTypeInventory, Data: json.RawMessage(`{"server_name":"x"}`)})
	store.Observe(output.Observation{Type: ObservationTypeIdentifiers, Data: json.RawMessage(`{not valid json`)})

	got := IdentifiersFrom(store)
	if len(got) != 1 {
		t.Fatalf("IdentifiersFrom len = %d, want 1 (other types + undecodable ignored)", len(got))
	}
	if got[0].Identity != "tenant-a" || len(got[0].Objects) != 1 || got[0].Objects[0].ID != "ord_1" {
		t.Errorf("decoded identifiers wrong: %+v", got[0])
	}
}

// A nil store yields no identifiers rather than panicking.
func TestIdentifiersFrom_NilStore(t *testing.T) {
	if got := IdentifiersFrom(nil); got != nil {
		t.Errorf("IdentifiersFrom(nil) = %v, want nil", got)
	}
}

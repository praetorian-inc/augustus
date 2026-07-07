package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// reconTarget implements types.Generator + types.MCPReconnaissance.
type reconTarget struct{ inv *types.MCPInventory }

func (reconTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (reconTarget) ClearHistory()       {}
func (reconTarget) Name() string        { return "recon-target" }
func (reconTarget) Description() string { return "recon-target" }
func (r reconTarget) MCPInventory(context.Context) (*types.MCPInventory, error) {
	return r.inv, nil
}

// plainTarget implements only types.Generator (no reconnaissance capability).
type plainTarget struct{}

func (plainTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainTarget) ClearHistory()       {}
func (plainTarget) Name() string        { return "plain" }
func (plainTarget) Description() string { return "plain" }

func newModule(t *testing.T) *MCP {
	t.Helper()
	m, err := New(registry.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m.(*MCP)
}

func TestMCP_EmitsInventoryObservation(t *testing.T) {
	inv := &types.MCPInventory{
		Transport:       "sse",
		ProtocolVersion: "2024-11-05",
		ServerName:      "acme-mcp",
		Capabilities:    types.MCPCapabilities{Tools: true},
		Tools:           []types.MCPTool{{Name: "echo"}},
		Counts:          types.MCPInventoryCounts{Tools: 1},
	}
	obs, err := newModule(t).Recon(context.Background(), reconTarget{inv: inv})
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	if o.Type != ObservationTypeInventory {
		t.Errorf("type = %q, want %q", o.Type, ObservationTypeInventory)
	}
	if o.Target != "acme-mcp" || o.Source != "recon.MCP" {
		t.Errorf("target/source = %q/%q", o.Target, o.Source)
	}
	var got types.MCPInventory
	if err := json.Unmarshal(o.Data, &got); err != nil {
		t.Fatalf("decode observation data: %v", err)
	}
	if got.ProtocolVersion != "2024-11-05" || len(got.Tools) != 1 || got.Tools[0].Name != "echo" {
		t.Errorf("inventory payload not carried: %+v", got)
	}
}

func TestMCP_SkipsNonReconTarget(t *testing.T) {
	obs, err := newModule(t).Recon(context.Background(), plainTarget{})
	if err != nil {
		t.Fatalf("Recon: %v", err)
	}
	if obs != nil {
		t.Errorf("expected nil observations for non-MCP target, got %+v", obs)
	}
}

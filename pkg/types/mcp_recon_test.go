package types

import (
	"encoding/json"
	"testing"
)

// ToolMaps must render an MCP inventory's tools in the SAME wire shape that
// ToolInvoker.ListTools produces (name / description / parameters), so probes
// can consume shared recon without a second enumeration.
func TestMCPInventory_ToolMaps(t *testing.T) {
	inv := &MCPInventory{
		Tools: []MCPTool{
			{
				Name:        "echo",
				Description: "Echoes the query back.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
			},
			{Name: "noschema"}, // tool with no input schema
		},
	}

	got := inv.ToolMaps()
	if len(got) != 2 {
		t.Fatalf("ToolMaps len = %d, want 2", len(got))
	}

	echo := got[0]
	if echo["name"] != "echo" {
		t.Errorf("name = %v, want echo", echo["name"])
	}
	if echo["description"] != "Echoes the query back." {
		t.Errorf("description = %v", echo["description"])
	}
	// parameters must decode to a map so toolsec.toolParams can read it.
	params, ok := echo["parameters"].(map[string]any)
	if !ok {
		t.Fatalf("parameters is %T, want map[string]any", echo["parameters"])
	}
	props, ok := params["properties"].(map[string]any)
	if !ok || props["query"] == nil {
		t.Errorf("properties.query missing: %v", params)
	}

	// A tool with no schema must still appear, without a parameters key.
	if got[1]["name"] != "noschema" {
		t.Errorf("second tool name = %v", got[1]["name"])
	}
	if _, has := got[1]["parameters"]; has {
		t.Errorf("noschema tool should have no parameters key, got %v", got[1]["parameters"])
	}
}

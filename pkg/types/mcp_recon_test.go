package types

import (
	"encoding/json"
	"strings"
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

// ToolMaps must expose safety annotations under "annotations" as a concrete
// MCPToolAnnotations value, so the tool-surface probes gate destructive tools the
// same way on the recon path as on the live-enumeration path.
func TestMCPInventory_ToolMaps_Annotations(t *testing.T) {
	tru := true
	inv := &MCPInventory{Tools: []MCPTool{
		{Name: "wipe", Annotations: &MCPToolAnnotations{Destructive: &tru}},
		{Name: "plain"},
	}}
	got := inv.ToolMaps()

	ann, ok := got[0]["annotations"].(MCPToolAnnotations)
	if !ok {
		t.Fatalf("annotations is %T, want MCPToolAnnotations", got[0]["annotations"])
	}
	if !ann.IsDestructive() {
		t.Error("wipe tool should report destructive")
	}
	if _, has := got[1]["annotations"]; has {
		t.Error("un-annotated tool must not carry an annotations key")
	}
}

func TestMCPToolAnnotations_IsDestructive(t *testing.T) {
	tru, fls := true, false
	tests := []struct {
		name string
		ann  *MCPToolAnnotations
		want bool
	}{
		{"nil annotations are not known-destructive", nil, false},
		{"read-only is never destructive", &MCPToolAnnotations{ReadOnly: true, Destructive: &tru}, false},
		{"explicit destructive", &MCPToolAnnotations{Destructive: &tru}, true},
		{"explicit non-destructive", &MCPToolAnnotations{Destructive: &fls}, false},
		{"non-read-only with no destructive hint defaults to destructive (MCP spec)", &MCPToolAnnotations{}, true},
	}
	for _, tt := range tests {
		if got := tt.ann.IsDestructive(); got != tt.want {
			t.Errorf("%s: IsDestructive() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// MCPIdentifiers/MCPObjectRef must round-trip through JSON with the documented
// keys; Source is omitempty while the other fields are always present. The ref is
// server-agnostic — it carries no fingerprint or field-name markers.
func TestMCPIdentifiers_JSONRoundTrip(t *testing.T) {
	in := MCPIdentifiers{
		Identity: "tenant-a",
		Objects: []MCPObjectRef{
			{
				Tool:   "get_order",
				Param:  "id",
				ID:     "ord_1",
				Source: "list_orders",
				Args:   map[string]any{"id": "ord_1"},
			},
			{
				Tool:  "get_ticket",
				Param: "ticket_id",
				ID:    "T-1",
				// Source intentionally omitted.
			},
		},
	}

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Documented wire keys must be present.
	for _, key := range []string{`"identity"`, `"objects"`, `"tool"`, `"param"`, `"id"`, `"source"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshaled payload missing key %s: %s", key, data)
		}
	}
	// The ref must NOT carry any response-format-specific evidence.
	for _, key := range []string{`"fingerprint"`, `"distinguishers"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("marshaled payload must not carry format-specific key %s: %s", key, data)
		}
	}
	// Source is omitempty: the second object must not emit a "source" field.
	var generic struct {
		Objects []map[string]json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v", err)
	}
	if _, has := generic.Objects[1]["source"]; has {
		t.Errorf("empty Source should be omitted, got %v", generic.Objects[1]["source"])
	}

	var out MCPIdentifiers
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Identity != "tenant-a" || len(out.Objects) != 2 {
		t.Fatalf("round-trip lost data: %+v", out)
	}
	got := out.Objects[0]
	if got.Tool != "get_order" || got.Param != "id" || got.ID != "ord_1" ||
		got.Source != "list_orders" || got.Args["id"] != "ord_1" {
		t.Errorf("first object not carried: %+v", got)
	}
}

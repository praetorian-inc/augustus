package mcpprobe

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/augustus/internal/toolsig"
)

// TestBenignValue_CoercesNonStringEnumToDeclaredType locks the fix for enum
// placeholders. Enum values are stored as strings, so a non-string enum
// ({"type":"integer","enum":[1,2]}) must be coerced back to its declared scalar
// type — otherwise the benign placeholder is submitted as "1" and rejected by
// schema validation before the call reaches the parameter under test.
func TestBenignValue_CoercesNonStringEnumToDeclaredType(t *testing.T) {
	cases := []struct {
		name string
		p    toolsig.Param
		want any
	}{
		{"integer enum", toolsig.Param{Type: "integer", Enum: []string{"1", "2"}}, 1},
		{"number enum", toolsig.Param{Type: "number", Enum: []string{"1.5", "2.5"}}, 1.5},
		{"boolean enum", toolsig.Param{Type: "boolean", Enum: []string{"true", "false"}}, true},
		{"string enum unchanged", toolsig.Param{Type: "string", Enum: []string{"read", "write"}}, "read"},
		{"malformed scalar enum falls back to the string", toolsig.Param{Type: "integer", Enum: []string{"notanint"}}, "notanint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := benignValue(tc.p); got != tc.want {
				t.Errorf("benignValue = %#v (%T), want %#v (%T)", got, got, tc.want, tc.want)
			}
		})
	}
}

// TestBenignArgs_FlatSchemaUnchanged is the regression gate for the migration off
// the flat parser: on a schema with no nesting and no conditionals, the arguments
// built must be exactly what the previous top-level-properties reader produced —
// every required parameter filled, every optional one absent, overrides applied
// last.
func TestBenignArgs_FlatSchemaUnchanged(t *testing.T) {
	tool := map[string]any{
		"name": "flat",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode":     map[string]any{"type": "string", "enum": []any{"read", "write"}},
				"count":    map[string]any{"type": "integer"},
				"enabled":  map[string]any{"type": "boolean"},
				"optional": map[string]any{"type": "string"},
				"target":   map[string]any{"type": "string"},
			},
			"required": []any{"mode", "count", "enabled", "target"},
		},
	}
	sigs := ToolSignatures(tool)
	if len(sigs) != 1 {
		t.Fatalf("ToolSignatures on a flat schema = %d signatures, want exactly 1", len(sigs))
	}
	got := BenignArgs(sigs[0], map[toolsig.Path]any{"target": "override"})
	want := map[string]any{
		"mode":    "read",
		"count":   1,
		"enabled": true,
		"target":  "override",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("BenignArgs = %#v, want %#v", got, want)
	}
}

// TestBenignArgs_PlacesNestedOverrideAtItsPath is what the flat parser could not
// do: a parameter nested inside an object must be addressed at its real path, or
// the value lands beside the object the server actually reads it from.
func TestBenignArgs_PlacesNestedOverrideAtItsPath(t *testing.T) {
	tool := map[string]any{
		"name": "fetch_object",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"params": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"object_id": map[string]any{"type": "string"},
					},
					"required": []any{"object_id"},
				},
			},
			"required": []any{"tenant_id", "params"},
		},
	}
	sigs := ToolSignatures(tool)
	if len(sigs) != 1 {
		t.Fatalf("ToolSignatures = %d signatures, want 1", len(sigs))
	}
	args := BenignArgs(sigs[0], map[toolsig.Path]any{"params.object_id": "obj_a1"})
	params, ok := args["params"].(map[string]any)
	if !ok {
		t.Fatalf("args[params] = %#v, want an object", args["params"])
	}
	if params["object_id"] != "obj_a1" {
		t.Errorf("args[params][object_id] = %#v, want %q", params["object_id"], "obj_a1")
	}
	if _, stray := args["object_id"]; stray {
		t.Error("the identifier was also written at the top level, where the server does not read it")
	}
}

// TestBenignCall_UnsetOmitsTheArgument covers the control leg of the
// credential-presence differential: the argument must be ABSENT, not present
// holding a placeholder, or the two legs are the same request.
func TestBenignCall_UnsetOmitsTheArgument(t *testing.T) {
	tool := map[string]any{
		"name": "admin_op",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action": map[string]any{"type": "string"},
				"token":  map[string]any{"type": "string"},
			},
			"required": []any{"action", "token"},
		},
	}
	sigs := ToolSignatures(tool)
	call := BenignCall(sigs[0])
	call.Unset("token")
	args := call.Args()
	if _, present := args["token"]; present {
		t.Errorf("args = %#v, want the token argument absent entirely", args)
	}
	if args["action"] != "test" {
		t.Errorf("args[action] = %#v, want the benign placeholder to survive", args["action"])
	}
}

// TestToolSignatures_NoParametersKeyIsANoArgumentTool: a tool declaring no
// schema takes no arguments. That is a description of the tool, and callers have
// always been able to invoke it with an empty argument object.
func TestToolSignatures_NoParametersKeyIsANoArgumentTool(t *testing.T) {
	sigs := ToolSignatures(map[string]any{"name": "get_status"})
	if len(sigs) != 1 {
		t.Fatalf("ToolSignatures = %d signatures, want 1", len(sigs))
	}
	if len(sigs[0].Params) != 0 {
		t.Errorf("signature has %d params, want none", len(sigs[0].Params))
	}
	if got := BenignArgs(sigs[0], nil); len(got) != 0 {
		t.Errorf("BenignArgs = %#v, want an empty argument object", got)
	}
}

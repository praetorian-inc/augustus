package mcp

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// envelopeGetter models the uniform-envelope tool shape that motivates the
// tool_args / tool_id_paths hints: two required top-level parameters that must be
// exactly right (a discriminator and an opaque tenant id) plus a nested object
// that carries the real arguments.
func envelopeGetter() toolSpec {
	return toolSpec{
		name: "upwork__get_account",
		params: []toolParam{
			{name: "action", typ: "string", required: true},
			{name: "org_uid", typ: "string", required: true},
			{name: "params", typ: "object", required: false},
		},
		idParam: "id",
	}
}

func newIdentifiers(t *testing.T, cfg registry.Config) *MCPIdentifiers {
	t.Helper()
	r, err := NewIdentifiers(cfg)
	if err != nil {
		t.Fatalf("NewIdentifiers: %v", err)
	}
	m, ok := r.(*MCPIdentifiers)
	if !ok {
		t.Fatalf("NewIdentifiers returned %T, want *MCPIdentifiers", r)
	}
	return m
}

// Without hints, buildGetterArgs must be byte-for-byte what benignArgs produced
// before this change: no existing target's behavior shifts.
func TestBuildGetterArgsUnchangedWithoutHints(t *testing.T) {
	m := newIdentifiers(t, registry.Config{})
	g := envelopeGetter()

	got := m.buildGetterArgs(g, "TARGET")
	want := benignArgs(g.params, g.idParam, "TARGET")

	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildGetterArgs = %v, want benignArgs output %v", got, want)
	}
	// Documents the pre-fix shape that the server rejects: placeholders in the
	// required discriminator/tenant params, identifier stranded at the top level.
	if got["action"] != "test" || got["org_uid"] != "test" {
		t.Errorf("expected synthesized placeholders, got %v", got)
	}
	if _, nested := got["params"]; nested {
		t.Errorf("params should not be populated without hints: %v", got)
	}
}

// With both hints, the same getter yields the envelope the server accepts.
func TestBuildGetterArgsAppliesEnvelopeHints(t *testing.T) {
	m := newIdentifiers(t, registry.Config{
		"tool_args": map[string]any{
			"upwork__get_account": map[string]any{
				"action":  "get_user_details",
				"org_uid": "2087392690628212517",
			},
		},
		"tool_id_paths": map[string]any{
			"upwork__get_account": "params.id",
		},
	})

	got := m.buildGetterArgs(envelopeGetter(), "VICTIM_ID")
	want := map[string]any{
		"action":  "get_user_details",
		"org_uid": "2087392690628212517",
		"params":  map[string]any{"id": "VICTIM_ID"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildGetterArgs = %v, want %v", got, want)
	}
	if _, flat := got["id"]; flat {
		t.Errorf("identifier left at top level: %v", got)
	}
}

// tool_args alone (no id path) still fixes the required discriminator/tenant
// params while leaving the caller's flat identifier placement intact — the right
// behavior for a server whose id genuinely is top level.
func TestBuildGetterArgsStaticOnlyKeepsFlatIdentifier(t *testing.T) {
	m := newIdentifiers(t, registry.Config{
		"tool_args": map[string]any{
			"upwork__get_account": map[string]any{"action": "get_user_details"},
		},
	})

	got := m.buildGetterArgs(envelopeGetter(), "TARGET")
	if got["action"] != "get_user_details" {
		t.Errorf("action = %v, want get_user_details", got["action"])
	}
	if got["id"] != "TARGET" {
		t.Errorf("id = %v, want TARGET at top level", got["id"])
	}
	if got["org_uid"] != "test" {
		t.Errorf("org_uid = %v, want untouched placeholder", got["org_uid"])
	}
}

// Hints are per tool: a tool with no entry is unaffected by another's.
func TestBuildGetterArgsHintsAreScopedPerTool(t *testing.T) {
	m := newIdentifiers(t, registry.Config{
		"tool_args":     map[string]any{"other_tool": map[string]any{"action": "x"}},
		"tool_id_paths": map[string]any{"other_tool": "params.id"},
	})
	g := envelopeGetter()

	got := m.buildGetterArgs(g, "TARGET")
	want := benignArgs(g.params, g.idParam, "TARGET")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildGetterArgs = %v, want unchanged %v", got, want)
	}
}

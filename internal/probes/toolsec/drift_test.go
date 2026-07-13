package toolsec

import "testing"

// driftTool builds a minimal tool snapshot map in the canonical ListTools shape.
func driftTool(name, desc string, params map[string]any) map[string]any {
	t := map[string]any{"name": name, "description": desc}
	if params != nil {
		t["parameters"] = params
	}
	return t
}

func TestDiffTools_AddedTool(t *testing.T) {
	base := []map[string]any{driftTool("a", "first", nil)}
	cur := []map[string]any{driftTool("a", "first", nil), driftTool("b", "second", nil)}

	changes := DiffTools(base, cur)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want exactly one", changes)
	}
	if changes[0].Name != "b" || changes[0].Kind != "added" {
		t.Errorf("change = %+v, want added tool b", changes[0])
	}
}

func TestDiffTools_RemovedTool(t *testing.T) {
	base := []map[string]any{driftTool("a", "first", nil), driftTool("b", "second", nil)}
	cur := []map[string]any{driftTool("a", "first", nil)}

	changes := DiffTools(base, cur)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want exactly one", changes)
	}
	if changes[0].Name != "b" || changes[0].Kind != "removed" {
		t.Errorf("change = %+v, want removed tool b", changes[0])
	}
}

func TestDiffTools_DescriptionChanged(t *testing.T) {
	base := []map[string]any{driftTool("a", "old description", nil)}
	cur := []map[string]any{driftTool("a", "new description", nil)}

	changes := DiffTools(base, cur)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want exactly one", changes)
	}
	if changes[0].Name != "a" || changes[0].Kind != "description_changed" {
		t.Errorf("change = %+v, want description_changed for a", changes[0])
	}
}

func TestDiffTools_ParametersChanged(t *testing.T) {
	base := []map[string]any{driftTool("a", "same", map[string]any{
		"type":       "object",
		"properties": map[string]any{"q": map[string]any{"type": "string"}},
	})}
	cur := []map[string]any{driftTool("a", "same", map[string]any{
		"type":       "object",
		"properties": map[string]any{"q": map[string]any{"type": "string"}, "extra": map[string]any{"type": "string"}},
	})}

	changes := DiffTools(base, cur)
	if len(changes) != 1 {
		t.Fatalf("changes = %+v, want exactly one", changes)
	}
	if changes[0].Name != "a" || changes[0].Kind != "parameters_changed" {
		t.Errorf("change = %+v, want parameters_changed for a", changes[0])
	}
}

// TestDiffTools_ReorderedRequiredSet: JSON-Schema "required" is an unordered set,
// so ["a","b"] vs ["b","a"] (otherwise identical) is NOT a real change.
func TestDiffTools_ReorderedRequiredSet(t *testing.T) {
	base := []map[string]any{driftTool("a", "same", map[string]any{
		"type":       "object",
		"properties": map[string]any{"a": map[string]any{"type": "string"}, "b": map[string]any{"type": "string"}},
		"required":   []any{"a", "b"},
	})}
	cur := []map[string]any{driftTool("a", "same", map[string]any{
		"type":       "object",
		"properties": map[string]any{"a": map[string]any{"type": "string"}, "b": map[string]any{"type": "string"}},
		"required":   []any{"b", "a"},
	})}

	changes := DiffTools(base, cur)
	if len(changes) != 0 {
		t.Fatalf("changes = %+v, want none for a reordered required set", changes)
	}
}

// TestDiffTools_ReorderedEnumSet: JSON-Schema "enum" is likewise an unordered
// set of allowed values; reordering it is not a change.
func TestDiffTools_ReorderedEnumSet(t *testing.T) {
	schema := func(enum ...any) map[string]any {
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode": map[string]any{"type": "string", "enum": enum},
			},
		}
	}
	base := []map[string]any{driftTool("a", "same", schema("read", "write"))}
	cur := []map[string]any{driftTool("a", "same", schema("write", "read"))}

	changes := DiffTools(base, cur)
	if len(changes) != 0 {
		t.Fatalf("changes = %+v, want none for a reordered enum set", changes)
	}
}

// TestDiffTools_ChangedRequiredSet: a genuine set membership change (different
// element, not just reordering) is still reported.
func TestDiffTools_ChangedRequiredSet(t *testing.T) {
	base := []map[string]any{driftTool("a", "same", map[string]any{
		"type":     "object",
		"required": []any{"a", "b"},
	})}
	cur := []map[string]any{driftTool("a", "same", map[string]any{
		"type":     "object",
		"required": []any{"a", "c"},
	})}

	changes := DiffTools(base, cur)
	if len(changes) != 1 || changes[0].Kind != "parameters_changed" {
		t.Fatalf("changes = %+v, want a parameters_changed for a genuine required-set change", changes)
	}
}

func TestDiffTools_Identical(t *testing.T) {
	tools := []map[string]any{
		driftTool("a", "first", map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}),
		driftTool("b", "second", nil),
	}
	// Independent but value-equal snapshots.
	base := []map[string]any{
		driftTool("a", "first", map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}),
		driftTool("b", "second", nil),
	}

	changes := DiffTools(base, tools)
	if len(changes) != 0 {
		t.Fatalf("changes = %+v, want none for identical snapshots", changes)
	}
}

func TestDiffTools_DeterministicOrder(t *testing.T) {
	base := []map[string]any{driftTool("z", "z", nil), driftTool("a", "a", nil)}
	cur := []map[string]any{driftTool("m", "m", nil)}

	// z removed, a removed, m added -> sorted by name: a, m, z.
	changes := DiffTools(base, cur)
	if len(changes) != 3 {
		t.Fatalf("changes = %+v, want three", changes)
	}
	want := []string{"a", "m", "z"}
	for i, w := range want {
		if changes[i].Name != w {
			t.Errorf("changes[%d].Name = %q, want %q (order not deterministic: %+v)", i, changes[i].Name, w, changes)
		}
	}
}

package toolargs

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// The zero Builder and an empty config must both leave call arguments exactly as
// the caller synthesized them: every existing target keeps its current behavior.
func TestNoConfigIsANoOp(t *testing.T) {
	for name, b := range map[string]Builder{
		"zero value":   {},
		"empty config": New(registry.Config{}),
	} {
		t.Run(name, func(t *testing.T) {
			if got := b.IDPath("tool"); got != "" {
				t.Fatalf("IDPath = %q, want empty", got)
			}
			args := map[string]any{"id": "X", "action": "test"}
			want := map[string]any{"id": "X", "action": "test"}

			if got := b.Apply("tool", args); !reflect.DeepEqual(got, want) {
				t.Errorf("Apply mutated args: %v, want %v", got, want)
			}
			if got := b.Place("tool", "id", "X", args); !reflect.DeepEqual(got, want) {
				t.Errorf("Place mutated args: %v, want %v", got, want)
			}
		})
	}
}

// Static args override the synthesized filler: they exist because the schema
// cannot supply the correct value (an opaque tenant id, an account uid).
func TestApplyOverridesSynthesizedFillers(t *testing.T) {
	b := New(registry.Config{
		"tool_args": map[string]any{
			"get_account": map[string]any{
				"action":  "get_user_details",
				"org_uid": "2087392690628212517",
			},
		},
	})

	got := b.Apply("get_account", map[string]any{
		"action":  "test", // placeholder the schema produced
		"org_uid": "test", // placeholder the schema produced
		"params":  map[string]any{},
	})
	want := map[string]any{
		"action":  "get_user_details",
		"org_uid": "2087392690628212517",
		"params":  map[string]any{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Apply = %v, want %v", got, want)
	}

	// A tool with no configured entry is untouched.
	other := map[string]any{"action": "test"}
	if got := b.Apply("find_jobs", other); !reflect.DeepEqual(got, map[string]any{"action": "test"}) {
		t.Errorf("unconfigured tool mutated: %v", got)
	}
}

func TestApplyOnNilArgs(t *testing.T) {
	b := New(registry.Config{
		"tool_args": map[string]any{"t": map[string]any{"k": "v"}},
	})
	got := b.Apply("t", nil)
	if !reflect.DeepEqual(got, map[string]any{"k": "v"}) {
		t.Errorf("Apply(nil) = %v, want {k:v}", got)
	}
	// Nil in, nil out when there is nothing to add.
	if got := b.Apply("unconfigured", nil); got != nil {
		t.Errorf("Apply(nil) on unconfigured tool = %v, want nil", got)
	}
}

// Place moves the identifier off the top level and into the nested object the
// server actually reads it from, creating the intermediate object.
func TestPlaceRelocatesIdentifierIntoNestedObject(t *testing.T) {
	b := New(registry.Config{
		"tool_id_paths": map[string]any{"get_account": "params.id"},
	})

	got := b.Place("get_account", "id", "TARGET", map[string]any{
		"id":      "TARGET", // flat placement the caller made
		"action":  "test",
		"org_uid": "test",
	})
	want := map[string]any{
		"action":  "test",
		"org_uid": "test",
		"params":  map[string]any{"id": "TARGET"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Place = %v, want %v", got, want)
	}
}

// The synthesized filler for an `object`-typed parameter is an empty map; the
// configured path must populate it rather than be discarded by it.
func TestPlacePopulatesExistingEmptyObject(t *testing.T) {
	b := New(registry.Config{
		"tool_id_paths": map[string]any{"t": "params.job_id"},
	})
	got := b.Place("t", "job_id", "J1", map[string]any{
		"job_id": "J1",
		"params": map[string]any{}, // benignValue("object")
	})
	want := map[string]any{"params": map[string]any{"job_id": "J1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Place = %v, want %v", got, want)
	}
}

// A non-object value sitting at an intermediate step is replaced: the configured
// path is an explicit statement about the tool's shape and outranks a filler.
func TestPlaceReplacesNonObjectIntermediate(t *testing.T) {
	b := New(registry.Config{
		"tool_id_paths": map[string]any{"t": "params.id"},
	})
	got := b.Place("t", "id", "X", map[string]any{"params": "test"})
	want := map[string]any{"params": map[string]any{"id": "X"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Place = %v, want %v", got, want)
	}
}

func TestPlaceUnconfiguredToolKeepsFlatPlacement(t *testing.T) {
	b := New(registry.Config{
		"tool_id_paths": map[string]any{"other": "params.id"},
	})
	args := map[string]any{"id": "X"}
	if got := b.Place("t", "id", "X", args); !reflect.DeepEqual(got, map[string]any{"id": "X"}) {
		t.Errorf("Place = %v, want flat placement preserved", got)
	}
}

func TestSetPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		args map[string]any
		want map[string]any
	}{
		{"top level", "id", map[string]any{}, map[string]any{"id": "V"}},
		{"one level", "params.id", map[string]any{}, map[string]any{"params": map[string]any{"id": "V"}}},
		{
			"deep", "a.b.c",
			map[string]any{},
			map[string]any{"a": map[string]any{"b": map[string]any{"c": "V"}}},
		},
		{
			"preserves siblings", "params.id",
			map[string]any{"params": map[string]any{"limit": 1}},
			map[string]any{"params": map[string]any{"limit": 1, "id": "V"}},
		},
		{"empty path ignored", "", map[string]any{"k": "v"}, map[string]any{"k": "v"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetPath(tc.args, tc.path, "V")
			if !reflect.DeepEqual(tc.args, tc.want) {
				t.Errorf("SetPath = %v, want %v", tc.args, tc.want)
			}
		})
	}
}

func TestSetPathOnNilMapDoesNotPanic(t *testing.T) {
	SetPath(nil, "params.id", "V") // must not panic
}

// Malformed hints are skipped, not fatal: a bad entry must not disable a scan
// that is still useful without it.
func TestMalformedConfigIsSkipped(t *testing.T) {
	b := New(registry.Config{
		"tool_args":     map[string]any{"t": "not-a-map", "u": map[string]any{}},
		"tool_id_paths": map[string]any{"t": 42, "u": ""},
	})
	if b.static != nil {
		t.Errorf("static = %v, want nil", b.static)
	}
	if b.idPath != nil {
		t.Errorf("idPath = %v, want nil", b.idPath)
	}
}

func TestWrongTypeConfigIsSkipped(t *testing.T) {
	b := New(registry.Config{"tool_args": "nope", "tool_id_paths": []string{"nope"}})
	if b.static != nil || b.idPath != nil {
		t.Errorf("expected no hints, got static=%v idPath=%v", b.static, b.idPath)
	}
}

// The end-to-end shape: a flat synthesized call becomes the envelope the server
// actually accepts.
func TestBuilderProducesServerAcceptedEnvelope(t *testing.T) {
	b := New(registry.Config{
		"tool_args": map[string]any{
			"upwork__get_account": map[string]any{
				"action":  "get_user_details",
				"org_uid": "2087392690628212517",
			},
		},
		"tool_id_paths": map[string]any{"upwork__get_account": "params.id"},
	})

	// What a caller synthesizes from the schema today.
	args := map[string]any{
		"id":      "VICTIM_ID",
		"action":  "test",
		"org_uid": "test",
		"params":  map[string]any{},
	}

	args = b.Place("upwork__get_account", "id", "VICTIM_ID", args)
	args = b.Apply("upwork__get_account", args)

	want := map[string]any{
		"action":  "get_user_details",
		"org_uid": "2087392690628212517",
		"params":  map[string]any{"id": "VICTIM_ID"},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("built args = %v, want %v", args, want)
	}
}

package mcptool

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/observed"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// objectSurface models the shape that makes the observed-value store necessary:
// a listing tool hands out identifiers, and two getters require one back — one
// at the top level, one nested inside an object. The identifier is declared as a
// bare string, so nothing in the schema, the description or any configuration
// can supply it. Only a caller that remembers what the listing returned can call
// the getters at all.
func objectSurface() []map[string]any {
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{
			"name":        "list_objects",
			"description": "Return the caller's objects.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"tenant_id": str},
				"required":   []any{"tenant_id"},
			},
		},
		{
			"name":        "get_object",
			"description": "Return one object by identifier.",
			"parameters": map[string]any{
				"type":       "object",
				"properties": map[string]any{"tenant_id": str, "object_id": str},
				"required":   []any{"tenant_id", "object_id"},
			},
		},
		{
			"name":        "fetch_object",
			"description": "Return one object by identifier, nested.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"tenant_id": str,
					"params": map[string]any{
						"type":       "object",
						"properties": map[string]any{"object_id": str},
						"required":   []any{"object_id"},
					},
				},
				"required": []any{"tenant_id", "params"},
			},
		},
	}
}

// TestProbeConsumesObservedValues is the end-to-end lock for the observed-value
// store: recon fills it, and a PROBE spends it.
//
// The store was verified as being FILLED, but nothing verified that a probe ever
// read a value out of it and put that value into a call. Without that step the
// whole mechanism is inert: the probe falls back to a placeholder, the server
// answers "no such object", and the tool is recorded as tested when the call
// never reached its logic.
//
// The identifier here exists nowhere but in the listing tool's response, so a
// call carrying it can have come from nowhere else.
func TestProbeConsumesObservedValues(t *testing.T) {
	values := observed.New()

	// Reconnaissance: the listing tool hands out identifiers, and the wrapped
	// invoker records them under this identity.
	listing := types.ToolResult{Text: `{"objects":[{"object_id":"obj_a1","name":"alpha report"}]}`}
	values.RecordCall(DefaultIdentity, "list_objects", map[string]any{"tenant_id": "TENANT-A"}, listing)

	var calls []map[string]any
	target := &mockTarget{
		tools: objectSurface(),
		call: func(name string, args map[string]any) types.ToolResult {
			if name != "list_objects" {
				calls = append(calls, args)
			}
			return types.ToolResult{Text: `{"ok":true}`}
		},
	}

	p, err := NewResponseLeak(registry.Config{})
	if err != nil {
		t.Fatalf("NewResponseLeak: %v", err)
	}
	aware, ok := p.(recon.ContextAwareProbe)
	if !ok {
		t.Fatal("mcptool.ResponseLeak does not consume shared reconnaissance, so it can never see an observed value")
	}
	aware.SetContext(recon.ProbeContext{Recon: recon.NewStore(), Observed: values})

	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(calls) == 0 {
		t.Fatal("the probe called no getter at all")
	}

	var sawTop, sawNested bool
	for _, args := range calls {
		if args["object_id"] == "obj_a1" {
			sawTop = true
		}
		if params, _ := args["params"].(map[string]any); params["object_id"] == "obj_a1" {
			sawNested = true
		}
	}
	if !sawTop {
		t.Error("no call carried object_id=obj_a1; the probe did not spend the observed identifier at the top level")
	}
	if !sawNested {
		t.Error("no call carried params.object_id=obj_a1; the probe did not spend the observed identifier at its nested path")
	}
}

// TestProbeDoesNotSpendAnotherIdentitysValues is the safety half of the same
// mechanism. Values are partitioned by the identity that saw them, and a probe
// running as one identity must not be handed another's — a scanner that
// auto-filled arguments across identities would manufacture cross-identity
// access out of its own plumbing and report it as a finding.
func TestProbeDoesNotSpendAnotherIdentitysValues(t *testing.T) {
	values := observed.New()
	values.RecordCall("secondary", "list_objects",
		map[string]any{"tenant_id": "TENANT-B"},
		types.ToolResult{Text: `{"objects":[{"object_id":"obj_b1"}]}`})

	var calls []map[string]any
	target := &mockTarget{
		tools: objectSurface(),
		call: func(name string, args map[string]any) types.ToolResult {
			if name != "list_objects" {
				calls = append(calls, args)
			}
			return types.ToolResult{Text: `{"ok":true}`}
		},
	}

	p, err := NewResponseLeak(registry.Config{})
	if err != nil {
		t.Fatalf("NewResponseLeak: %v", err)
	}
	p.(recon.ContextAwareProbe).SetContext(recon.ProbeContext{Recon: recon.NewStore(), Observed: values})
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, args := range calls {
		params, _ := args["params"].(map[string]any)
		if args["object_id"] == "obj_b1" || params["object_id"] == "obj_b1" {
			t.Fatalf("a probe running as %q spent an identifier only %q ever saw: %v", DefaultIdentity, "secondary", args)
		}
	}
}

// TestObservedStoreIgnoresEchoedArguments locks the fix for a measured
// poisoning. A server that repeats its input — and many do, in a confirmation
// block or a validation message — used to fill the store with the scanner's own
// placeholders and sentinels. Because the newest value wins, that junk then
// outranked the identifiers the target had genuinely handed out.
func TestObservedStoreIgnoresEchoedArguments(t *testing.T) {
	values := observed.New()
	// A real listing: the identifiers are the server's own.
	values.RecordCall(DefaultIdentity, "list_objects",
		map[string]any{"tenant_id": "TENANT-A"},
		types.ToolResult{Text: `{"objects":[{"object_id":"obj_a1"}]}`})
	// A later probe call whose response echoes the placeholder it was sent.
	values.RecordCall(DefaultIdentity, "get_object",
		map[string]any{"tenant_id": "TENANT-A", "object_id": "aug-nonexistent-83"},
		types.ToolResult{Text: `{"received":{"object_id":"aug-nonexistent-83"},"error":"no such object"}`})

	for _, v := range values.Values("object_id") {
		if s, _ := v.V.(string); strings.HasPrefix(s, "aug-nonexistent") {
			t.Fatalf("the store kept a value the scanner itself sent (%q); every later call would be built out of it", s)
		}
	}
	got := values.Values("object_id")
	if len(got) != 1 || got[0].V != "obj_a1" {
		t.Errorf("observed object_id = %v, want the one identifier the server actually handed out", got)
	}
}

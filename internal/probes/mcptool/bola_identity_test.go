package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// seedTenantScopedSurface models the shape most multi-tenant tool surfaces
// actually have: identity is carried in an ARGUMENT on every call, not in the
// transport. Both identities reach the same endpoint over the same session and
// differ only in tenant_id.
//
// One getter takes the object identifier at the top level and one takes it
// nested inside an object, because a name-addressed replay gets the nested one
// wrong in the most damaging way — the real identifier survives untouched inside
// the object.
func seedTenantScopedSurface(t *testing.T, store *recon.Store) {
	t.Helper()
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "primary",
		Objects: []types.MCPObjectRef{
			{
				Tool: "get_object", Param: "object_id", ParamPath: "object_id",
				ID: "obj_a1", Source: "list_objects",
				Args: map[string]any{"object_id": "obj_a1", "tenant_id": "TENANT-A"},
			},
			{
				Tool: "fetch_object", Param: "object_id", ParamPath: "params.object_id",
				ID: "obj_a1", Source: "list_objects",
				Args: map[string]any{"tenant_id": "TENANT-A", "params": map[string]any{"object_id": "obj_a1"}},
			},
		},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "secondary",
		Objects: []types.MCPObjectRef{
			{
				Tool: "get_object", Param: "object_id", ParamPath: "object_id",
				ID: "obj_b1", Source: "list_objects",
				Args: map[string]any{"object_id": "obj_b1", "tenant_id": "TENANT-B"},
			},
			{
				Tool: "fetch_object", Param: "object_id", ParamPath: "params.object_id",
				ID: "obj_b1", Source: "list_objects",
				Args: map[string]any{"tenant_id": "TENANT-B", "params": map[string]any{"object_id": "obj_b1"}},
			},
		},
	})
}

// TestBOLA_AttackSpeaksAsTheAttacker is the regression gate for a measured false
// positive.
//
// The probe used to replay the victim's ENTIRE validated argument map. On a
// surface where identity is an argument, that map contains the victim's tenant,
// so the "attack" asked as the victim — and a server enforcing ownership
// perfectly correctly returned the victim's object every time. Measured live
// against a lab server that is not vulnerable: every replay was served, and the
// detector saw a served-shaped response for each one.
//
// Only the IDENTIFIER may cross the identity boundary. Everything else must be
// the attacker's own.
func TestBOLA_AttackSpeaksAsTheAttacker(t *testing.T) {
	store := recon.NewStore()
	seedTenantScopedSurface(t, store)

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "primary"})
	p.SetContext(recon.ProbeContext{Recon: store})

	target := &recordingTarget{reply: func(_ string, _ map[string]any) types.ToolResult {
		return types.ToolResult{Text: `{"error":"not authorized for this object"}`}
	}}
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(target.calls) == 0 {
		t.Fatal("the probe issued no calls at all")
	}

	for _, c := range target.calls {
		if got := c.args["tenant_id"]; got != "TENANT-A" {
			t.Errorf("%s was called with tenant_id=%v; the attack must speak as the attacker (TENANT-A), never as the victim", c.name, got)
		}
	}

	// The victim's identifier must still arrive, at the path each getter reads it
	// from.
	var sawTop, sawNested bool
	for _, c := range target.calls {
		switch c.name {
		case "get_object":
			if c.args["object_id"] == "obj_b1" {
				sawTop = true
			}
		case "fetch_object":
			params, _ := c.args["params"].(map[string]any)
			if params["object_id"] == "obj_b1" {
				sawNested = true
			}
			if _, stray := c.args["object_id"]; stray {
				t.Error("fetch_object received object_id at the top level, where it does not read it")
			}
		}
	}
	if !sawTop {
		t.Error("the victim's identifier never reached get_object at object_id")
	}
	if !sawNested {
		t.Error("the victim's identifier never reached fetch_object at params.object_id")
	}
}

// TestBOLA_NamesArgumentsInheritedFromTheVictim: where the attacker has no value
// of its own for an argument, the attack has to inherit the victim's. That is not
// silently acceptable — if the inherited argument carries identity, the call is
// not the attacker's and a served response proves nothing. The paths travel with
// the attempt so a reviewer can see exactly what was borrowed.
func TestBOLA_NamesArgumentsInheritedFromTheVictim(t *testing.T) {
	store := recon.NewStore()
	// The attacker owns an object via a DIFFERENT tool, so it supplies no value
	// for the victim getter's region argument.
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "primary",
		Objects: []types.MCPObjectRef{{
			Tool: "get_note", Param: "note_id", ParamPath: "note_id",
			ID: "note_a", Args: map[string]any{"note_id": "note_a"},
		}},
	})
	observeIdentifiers(t, store, types.MCPIdentifiers{
		Identity: "secondary",
		Objects: []types.MCPObjectRef{{
			Tool: "get_object", Param: "object_id", ParamPath: "object_id",
			ID: "obj_b1", Args: map[string]any{"object_id": "obj_b1", "region": "eu-west"},
		}},
	})

	p := newBOLAProbe(t, registry.Config{"attacker_identity_label": "primary"})
	p.SetContext(recon.ProbeContext{Recon: store})
	target := &recordingTarget{reply: func(_ string, _ map[string]any) types.ToolResult {
		return types.ToolResult{Text: `{"ok":true}`}
	}}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}
	if got := attempts[0].Metadata[metaBOLAInheritedArgs]; got != "region" {
		t.Errorf("inherited arguments = %v, want %q so a reviewer can see what the attack borrowed from the victim", got, "region")
	}
}

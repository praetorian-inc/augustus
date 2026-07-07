package recon

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

type fakeGen struct{}

func (fakeGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (fakeGen) ClearHistory()       {}
func (fakeGen) Name() string        { return "fake" }
func (fakeGen) Description() string { return "fake" }

type fakeRecon struct {
	name string
	obs  []output.Observation
	err  error
}

func (f *fakeRecon) Name() string { return f.name }
func (f *fakeRecon) Recon(context.Context, types.Generator) ([]output.Observation, error) {
	return f.obs, f.err
}

func TestStore(t *testing.T) {
	s := NewStore()
	if s.Len() != 0 {
		t.Fatalf("new store len = %d, want 0", s.Len())
	}
	s.Observe(output.Observation{Type: "a"})
	s.Observe(output.Observation{Type: "b"})
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2", s.Len())
	}
	got := s.Observations()
	if len(got) != 2 || got[0].Type != "a" || got[1].Type != "b" {
		t.Fatalf("observations = %+v", got)
	}
	// Returned slice is a copy: mutating it must not affect the store.
	got[0].Type = "mutated"
	if s.Observations()[0].Type != "a" {
		t.Error("Observations() did not return an independent copy")
	}
}

func TestRun_StampsSourceAndAggregatesErrors(t *testing.T) {
	ok := &fakeRecon{name: "recon.OK", obs: []output.Observation{{Type: "x"}}} // Source empty → stamped
	boom := &fakeRecon{name: "recon.Boom", err: errors.New("kaboom")}
	sourced := &fakeRecon{name: "recon.OK", obs: []output.Observation{{Type: "y", Source: "explicit"}}}

	store := NewStore()
	err := Run(context.Background(), fakeGen{}, []Recon{ok, boom, sourced}, store)

	// Best-effort: the failing module doesn't stop the others.
	obs := store.Observations()
	if len(obs) != 2 {
		t.Fatalf("expected 2 observations despite one module failing, got %d", len(obs))
	}
	if obs[0].Source != "recon.OK" {
		t.Errorf("Source not stamped from module name: %q", obs[0].Source)
	}
	if obs[1].Source != "explicit" {
		t.Errorf("explicit Source overwritten: %q", obs[1].Source)
	}
	if err == nil || !contains(err.Error(), "recon.Boom") {
		t.Errorf("aggregated error should name the failing module, got %v", err)
	}
}

func TestRegistry(t *testing.T) {
	Register("recon.Test", func(registry.Config) (Recon, error) {
		return &fakeRecon{name: "recon.Test"}, nil
	})
	if _, ok := Get("recon.Test"); !ok {
		t.Fatal("recon.Test not registered")
	}
	m, err := Create("recon.Test", registry.Config{})
	if err != nil || m.Name() != "recon.Test" {
		t.Fatalf("Create = %v, %v", m, err)
	}
	found := false
	for _, n := range List() {
		if n == "recon.Test" {
			found = true
		}
	}
	if !found {
		t.Error("recon.Test not in List()")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

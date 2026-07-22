package recon

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestCreateAll_SkipsFailuresAndAggregates(t *testing.T) {
	Register("recon.CreateOK", func(registry.Config) (Recon, error) {
		return &fakeRecon{name: "recon.CreateOK"}, nil
	})
	Register("recon.CreateBoom", func(registry.Config) (Recon, error) {
		return nil, errors.New("bad config")
	})

	mods, err := CreateAll([]string{"recon.CreateOK", "recon.CreateBoom", "recon.Unknown"}, nil)
	// The one good module still builds; the two failures are aggregated.
	if len(mods) != 1 || mods[0].Name() != "recon.CreateOK" {
		t.Fatalf("modules = %+v, want just recon.CreateOK", mods)
	}
	if err == nil || !contains(err.Error(), "recon.CreateBoom") || !contains(err.Error(), "recon.Unknown") {
		t.Fatalf("err = %v, want both failing names", err)
	}
}

func TestCreateAll_PassesResolvedConfig(t *testing.T) {
	var gotCfg registry.Config
	Register("recon.CfgCapture", func(c registry.Config) (Recon, error) {
		gotCfg = c
		return &fakeRecon{name: "recon.CfgCapture"}, nil
	})

	resolve := func(name string) registry.Config { return registry.Config{"who": name} }
	if _, err := CreateAll([]string{"recon.CfgCapture"}, resolve); err != nil {
		t.Fatalf("CreateAll err = %v", err)
	}
	if gotCfg["who"] != "recon.CfgCapture" {
		t.Fatalf("resolved config not passed to factory: %+v", gotCfg)
	}
}

func TestRunAll_RunsWhatConstructedAndJoinsErrors(t *testing.T) {
	Register("recon.RunOK", func(registry.Config) (Recon, error) {
		return &fakeRecon{name: "recon.RunOK", obs: []output.Observation{{Type: "z"}}}, nil
	})
	Register("recon.RunCreateBoom", func(registry.Config) (Recon, error) {
		return nil, errors.New("nope")
	})

	store := NewStore()
	err := RunAll(context.Background(), fakeGen{},
		[]string{"recon.RunOK", "recon.RunCreateBoom"}, nil, store)

	// The good module ran (observation recorded) despite the sibling's failure.
	if store.Len() != 1 || store.Observations()[0].Type != "z" {
		t.Fatalf("store = %+v, want one observation", store.Observations())
	}
	if err == nil || !contains(err.Error(), "recon.RunCreateBoom") {
		t.Fatalf("err = %v, want the construction failure surfaced", err)
	}
}

func TestRunAll_CleanRunReturnsNil(t *testing.T) {
	Register("recon.RunClean", func(registry.Config) (Recon, error) {
		return &fakeRecon{name: "recon.RunClean", obs: []output.Observation{{Type: "ok"}}}, nil
	})
	store := NewStore()
	if err := RunAll(context.Background(), fakeGen{}, []string{"recon.RunClean"}, nil, store); err != nil {
		t.Fatalf("RunAll err = %v, want nil", err)
	}
}

// ctxProbe records whether SetContext was called and with which store.
type ctxProbe struct{ got *Store }

func (p *ctxProbe) SetContext(pc ProbeContext) { p.got = pc.Recon }

type plainProbe struct{}

func TestInjectProbeContext(t *testing.T) {
	store := NewStore()
	aware := &ctxProbe{}
	// Mixed slice of an aware and a non-aware item; only the aware one is touched.
	items := []any{aware, plainProbe{}}
	InjectProbeContext(items, store)
	if aware.got != store {
		t.Fatalf("aware probe did not receive the store (got %v)", aware.got)
	}
}

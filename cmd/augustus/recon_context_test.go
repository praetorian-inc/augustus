package main

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ctxProbe is a probe that records the recon store it was given.
type ctxProbe struct {
	got *recon.Store
}

func (c *ctxProbe) Probe(context.Context, types.Generator) ([]*attempt.Attempt, error) {
	return nil, nil
}
func (c *ctxProbe) Name() string                     { return "ctx.Probe" }
func (c *ctxProbe) SetContext(pc recon.ProbeContext) { c.got = pc.Recon }

// plainProbe does not implement ContextAwareProbe.
type plainProbe struct{}

func (plainProbe) Probe(context.Context, types.Generator) ([]*attempt.Attempt, error) {
	return nil, nil
}
func (plainProbe) Name() string { return "plain.Probe" }

// injectProbeContext must deliver the store to context-aware probes and leave
// others untouched (no panic, no interface required).
func TestInjectProbeContext(t *testing.T) {
	store := recon.NewStore()
	aware := &ctxProbe{}
	plain := plainProbe{}

	injectProbeContext([]probes.Prober{aware, plain}, store)

	if aware.got != store {
		t.Errorf("context-aware probe did not receive the shared store: got %v", aware.got)
	}
	// plainProbe simply must not have caused a panic; nothing else to assert.
}

package main

import (
	"context"
	"errors"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Fake recon modules used by the recon-only scan tests, registered once so the
// scan command's createRecons can resolve them by name.
const (
	reconFakeOK    = "recon.fakeOK"
	reconFakeEmpty = "recon.fakeEmpty"
	reconFakeErr   = "recon.fakeErr"
)

type fakeRecon struct {
	name string
	obs  []output.Observation
	err  error
}

func (f fakeRecon) Name() string { return f.name }

func (f fakeRecon) Recon(context.Context, types.Generator) ([]output.Observation, error) {
	return f.obs, f.err
}

func init() {
	recon.Register(reconFakeOK, func(registry.Config) (recon.Recon, error) {
		return fakeRecon{name: reconFakeOK, obs: []output.Observation{{Type: "fake.observation", Target: "t"}}}, nil
	})
	recon.Register(reconFakeEmpty, func(registry.Config) (recon.Recon, error) {
		return fakeRecon{name: reconFakeEmpty}, nil // no observations, no error (a skip-like result)
	})
	recon.Register(reconFakeErr, func(registry.Config) (recon.Recon, error) {
		return fakeRecon{name: reconFakeErr, err: errors.New("target unreachable")}, nil
	})
}

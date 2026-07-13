// Package recon provides reconnaissance modules and the registry for them.
//
// Reconnaissance is a first-class assessment activity, distinct from probing.
// A probe TESTS a target and yields a scored verdict; a Recon module MEASURES a
// target and yields descriptive facts (output.Observations). The distinction is
// enforced by the type system: a Recon returns Observations, not scored
// attempts, so it structurally cannot carry a verdict — there is no detector or
// pass/fail in this path. This mirrors Metasploit's auxiliary-vs-exploit split
// (recon populates the workspace; exploits act on it).
//
// Observations produced here flow into the shared Store, which is (a) serialized
// to scan output for viewing and (b) available to feed downstream probes.
package recon

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/output"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Recon is the interface every reconnaissance module implements. It gathers
// descriptive facts about the target and returns them as observations. It has
// no detector and produces no verdict.
type Recon interface {
	// Recon runs against the target generator and returns the observations it
	// gathered. Modules that cannot operate against the given target (e.g. the
	// generator lacks the needed capability) return no observations and no error.
	Recon(ctx context.Context, gen types.Generator) ([]output.Observation, error)
	// Name returns the fully qualified module name (e.g. "recon.MCP").
	Name() string
}

// Registry is the global recon-module registry, a peer to the probe, detector,
// generator, and buff registries.
var Registry = registry.New[Recon]("recon")

// Register adds a recon-module factory to the global registry.
func Register(name string, factory func(registry.Config) (Recon, error)) {
	Registry.Register(name, factory)
}

// List returns all registered recon-module names.
func List() []string {
	return Registry.List()
}

// Get retrieves a recon-module factory by name.
func Get(name string) (func(registry.Config) (Recon, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a recon module by name.
func Create(name string, cfg registry.Config) (Recon, error) {
	return Registry.Create(name, cfg)
}

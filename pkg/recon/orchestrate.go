package recon

import (
	"context"
	"errors"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ConfigResolver yields the registry.Config for a recon module by name. It lets
// callers control per-module configuration without recon depending on the
// config package: the CLI passes (*config.Config).ResolveReconConfig; an
// embedder can wrap that to inject its own settings (e.g. an LLM navigator
// generator). A nil resolver — or a nil result — means "no config", and Create
// is expected to be nil-safe.
type ConfigResolver func(name string) registry.Config

// CreateAll instantiates the named recon modules, resolving each module's config
// via resolve. It is best-effort: a module that fails to construct is skipped
// rather than aborting the batch, and every construction error is returned
// joined so the caller can surface degraded reconnaissance. Whatever
// constructed is returned and is safe to pass to Run.
func CreateAll(names []string, resolve ConfigResolver) ([]Recon, error) {
	mods := make([]Recon, 0, len(names))
	var errs []error
	for _, name := range names {
		var cfg registry.Config
		if resolve != nil {
			cfg = resolve(name)
		}
		m, err := Create(name, cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("create recon module %s: %w", name, err))
			continue
		}
		mods = append(mods, m)
	}
	return mods, errors.Join(errs...)
}

// RunAll creates the named recon modules (see CreateAll) and runs them into
// store, returning the construction and run errors joined. The run proceeds with
// whatever modules constructed, so one misconfigured module never blocks the
// rest. This is the single entry point for the standard reconnaissance phase:
// both the CLI scan flow and external embedders (e.g. Guard) should call it
// rather than re-implementing the create-then-run loop.
func RunAll(ctx context.Context, gen types.Generator, names []string, resolve ConfigResolver, store *Store) error {
	mods, createErr := CreateAll(names, resolve)
	runErr := Run(ctx, gen, mods, store)
	return errors.Join(createErr, runErr)
}

// InjectProbeContext delivers the shared reconnaissance store to every item that
// opts in via ContextAwareProbe; items that do not implement it are left
// untouched. It is generic over the concrete probe slice type so recon need not
// import the probes package. Call it on the RAW probe list before buff-wrapping
// — buffed probes do not forward ContextAwareProbe.
func InjectProbeContext[T any](items []T, store *Store) {
	pc := ProbeContext{Recon: store}
	for _, it := range items {
		if aware, ok := any(it).(ContextAwareProbe); ok {
			aware.SetContext(pc)
		}
	}
}

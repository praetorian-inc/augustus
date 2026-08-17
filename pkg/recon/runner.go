package recon

import (
	"context"
	"errors"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/types"
)

// Run executes each recon module against the target and records the observations
// it returns into store. Reconnaissance is best-effort: a module that fails does
// not abort the others; its error is aggregated and returned so a failure is
// surfaced rather than silently dropped. The module name is stamped as each
// observation's Source (provenance) unless the module set one itself.
func Run(ctx context.Context, gen types.Generator, modules []Recon, store *Store) error {
	var errs []error
	for _, m := range modules {
		// Opt-in: give modules that consume earlier observations the live store
		// before they run. Modules run in order and their output is recorded
		// below before the next iteration, so a later module sees earlier facts.
		if aware, ok := m.(ContextAwareRecon); ok {
			aware.SetContext(ProbeContext{Recon: store, Observed: store.Values()})
		}
		obs, err := m.Recon(ctx, gen)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.Name(), err))
			continue
		}
		for i := range obs {
			if obs[i].Source == "" {
				obs[i].Source = m.Name()
			}
			store.Observe(obs[i])
		}
	}
	return errors.Join(errs...)
}

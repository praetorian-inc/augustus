package runtimetemplates

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

// RegisterFromPath loads probe templates from a filesystem directory and
// registers them in the global probe registry, enabling runtime-defined probes
// (both static and multi-turn) without recompiling Augustus.
//
// It returns the IDs of the registered probes. Loading is atomic and fail-closed:
//   - if any template is invalid, nothing is registered;
//   - if a template's ID collides with an already-registered probe (e.g. a
//     built-in), nothing is registered unless allowOverride is true. This keeps a
//     stray template from silently shadowing a built-in probe.
func RegisterFromPath(dir string, allowOverride bool) ([]string, error) {
	tmpls, err := templates.LoadFromPath(dir)
	if err != nil {
		return nil, err
	}

	// Detect collisions before registering anything (atomic, fail-closed).
	var collisions []string
	for _, tmpl := range tmpls {
		if _, exists := probes.Get(tmpl.ID); exists {
			collisions = append(collisions, tmpl.ID)
		}
	}
	if len(collisions) > 0 && !allowOverride {
		return nil, fmt.Errorf("runtime template(s) would override existing probe(s): %s — pass --force to override",
			strings.Join(collisions, ", "))
	}

	ids := make([]string, 0, len(tmpls))
	for _, tmpl := range tmpls {
		if _, exists := probes.Get(tmpl.ID); exists {
			slog.Warn("runtime template overriding existing probe (--force)", "id", tmpl.ID)
		}
		probes.Register(tmpl.ID, factoryFor(tmpl))
		ids = append(ids, tmpl.ID)
	}
	return ids, nil
}

// factoryFor returns the probe factory appropriate for the template's type.
func factoryFor(tmpl *templates.ProbeTemplate) func(registry.Config) (probes.Prober, error) {
	if tmpl.IsMultiTurn() {
		return func(cfg registry.Config) (probes.Prober, error) {
			return newMultiTurnProbe(tmpl, cfg)
		}
	}
	return func(_ registry.Config) (probes.Prober, error) {
		return templates.NewTemplateProbe(tmpl), nil
	}
}

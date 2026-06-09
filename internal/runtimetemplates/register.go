package runtimetemplates

import (
	"log/slog"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

// RegisterFromPath loads probe templates from a filesystem directory and
// registers them in the global probe registry, enabling runtime-defined probes
// (both static and multi-turn) without recompiling Augustus.
//
// It returns the IDs of the registered probes. Loading fails if any template is
// invalid; the directory is loaded atomically (nothing is registered on error).
func RegisterFromPath(dir string) ([]string, error) {
	tmpls, err := templates.LoadFromPath(dir)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(tmpls))
	for _, tmpl := range tmpls {
		if _, exists := probes.Get(tmpl.ID); exists {
			slog.Warn("runtime template overrides an already-registered probe", "id", tmpl.ID)
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

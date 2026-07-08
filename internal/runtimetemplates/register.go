package runtimetemplates

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/detectors"
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
//     built-in), nothing is registered. A runtime template must not shadow an
//     existing probe; give the template a distinct id instead.
func RegisterFromPath(dir string) ([]string, error) {
	tmpls, err := templates.LoadFromPath(dir)
	if err != nil {
		return nil, err
	}

	// Pre-flight validation before registering anything (atomic, fail-closed):
	//   1. duplicate IDs within this batch,
	//   2. multi-turn strategy templates that fail to compile/dry-run,
	//   3. detector names (primary + secondary) that are not registered,
	//   4. collisions with already-registered probes.
	batch := make(map[string]bool, len(tmpls))
	var collisions []string
	for _, tmpl := range tmpls {
		if batch[tmpl.ID] {
			return nil, fmt.Errorf("duplicate template id %q in %s — each template must have a unique id", tmpl.ID, dir)
		}
		batch[tmpl.ID] = true

		// Compile multi-turn strategy prompts now so a bad field reference
		// (e.g. {{.Tpyo}}) aborts at load, not when the scan materializes the probe.
		if tmpl.IsMultiTurn() {
			maxTurns := 0
			if tmpl.Engine != nil {
				maxTurns = tmpl.Engine.MaxTurns
			}
			if _, err := newTemplateStrategy(tmpl.ID, tmpl.Strategy, maxTurns); err != nil {
				return nil, fmt.Errorf("invalid multi-turn template %q: %w", tmpl.ID, err)
			}
		}

		// Resolve detector names against the registry now so an unknown
		// info.detector / secondary_detector fails at load rather than partway
		// through a scan. All built-in detectors register at init, so by the
		// time a scan calls this they are present.
		if err := validateDetectorNames(tmpl); err != nil {
			return nil, err
		}

		if _, exists := probes.Get(tmpl.ID); exists {
			collisions = append(collisions, tmpl.ID)
		}
	}
	if len(collisions) > 0 {
		return nil, fmt.Errorf("runtime template(s) collide with existing probe id(s): %s — rename the template id(s) to avoid shadowing built-in probes",
			strings.Join(collisions, ", "))
	}

	ids := make([]string, 0, len(tmpls))
	for _, tmpl := range tmpls {
		probes.Register(tmpl.ID, factoryFor(tmpl))
		ids = append(ids, tmpl.ID)
	}
	return ids, nil
}

// validateDetectorNames ensures the template's primary detector and any
// secondary detectors resolve to registered detectors. Names are trimmed to
// match the registry lookup used at scan time.
func validateDetectorNames(tmpl *templates.ProbeTemplate) error {
	if name := strings.TrimSpace(tmpl.Info.Detector); name != "" {
		if _, ok := detectors.Get(name); !ok {
			return fmt.Errorf("template %q references unknown detector %q (info.detector) — not in the detector registry", tmpl.ID, name)
		}
	}
	for _, sd := range tmpl.Info.SecondaryDetectors {
		name := strings.TrimSpace(sd.Name)
		if name == "" {
			continue // empty-name validation is handled by template Validate()
		}
		if _, ok := detectors.Get(name); !ok {
			return fmt.Errorf("template %q references unknown secondary detector %q — not in the detector registry", tmpl.ID, name)
		}
	}
	return nil
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

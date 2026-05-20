// Package memoryinject provides probes for persistent memory injection attacks
// on LLM agents.
//
// These probes test whether agent memory systems can be poisoned through:
//   - MINJA: query-only memory injection without write access
//   - ER-MIA: cross-session reasoning corruption via misleading memories
//   - SpAIware: persistent spyware planted via indirect prompt injection
//   - Zombie Agent: self-reinforcing payloads that survive memory cleanup
package memoryinject

import (
	"embed"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

//go:embed data/*.yaml
var templateData embed.FS

func init() {
	loader := templates.NewLoader(templateData, "data")
	tmpls, err := loader.LoadAll()
	if err != nil {
		panic(fmt.Sprintf("memoryinject: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

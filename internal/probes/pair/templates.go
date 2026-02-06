package pair

import (
	"embed"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

//go:embed data/*.yaml
var templateData embed.FS

// NOTE: These YAML templates register static one-shot probes (pair.PAIR, pair.PAIRBasic).
// They send single hardcoded prompts, NOT the iterative PAIR algorithm.
// For the real algorithm, see pair.IterativePAIR in pair.go.
func init() {
	loader := templates.NewLoader(templateData, "data")
	tmpls, err := loader.LoadAll()
	if err != nil {
		panic(fmt.Sprintf("pair: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		// Capture tmpl in closure
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

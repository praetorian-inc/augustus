// Package reasoning provides probes targeting reasoning model-specific
// attack vectors (o1/o3/R1/Gemini Thinking).
//
// These probes test vulnerabilities in the thinking/reasoning mechanism:
//   - H-CoT: adversarial chain-of-thought prefix injection
//   - ShadowCoT: logically coherent but adversarially steered reasoning
//   - OverThink: computational DoS via excessive reasoning token usage
//   - DecisionHijack: spurious decision criteria injection
package reasoning

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
		panic(fmt.Sprintf("reasoning: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

package tap

import (
	"embed"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

//go:embed data/*.yaml
var templateData embed.FS

// NOTE: These YAML templates register static one-shot probes (tap.TAPv1, tap.TAPv2).
// They send single hardcoded prompts, NOT the iterative TAP algorithm.
// For the real algorithm, see tap.IterativeTAP in tap.go.
func init() {
	loader := templates.NewLoader(templateData, "data")
	tmpls, err := loader.LoadAll()
	if err != nil {
		panic(fmt.Sprintf("tap: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

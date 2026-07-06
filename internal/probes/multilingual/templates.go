package multilingual

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
		panic(fmt.Sprintf("multilingual: failed to load templates: %v", err))
	}
	for _, tmpl := range tmpls {
		t := tmpl
		probes.Register(t.ID, func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		})
	}
}

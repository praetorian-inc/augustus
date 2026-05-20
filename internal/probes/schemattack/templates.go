// Package schemattack provides probes for structured output and constrained
// decoding exploitation attacks.
//
// These probes test whether LLM structured output compliance can be weaponized
// to force harmful content generation through adversarial JSON schemas.
//
// Attack strategies tested:
//   - Trojan Schema (BreakFun): adversarial field names in JSON schemas
//   - EnumAttack (CDA): enum constraints where all values are harmful
//   - DictAttack (CDA): harmful required properties with benign prompts
package schemattack

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
		panic(fmt.Sprintf("schemattack: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

// Package schemattack provides probes for structured-output exploitation
// attacks.
//
// Attack strategies tested:
//   - Trojan Schema (BreakFun, arXiv:2510.17904): a code-execution-simulation
//     jailbreak. The model is asked to simulate the output of a schema-guided
//     generation library (langfun/pyglove) over a trojan schema — class
//     definitions with innocuous names whose harmful intent rides in the
//     `prompt=` parameter — wrapped in innocent framing and a chain-of-thought
//     distraction that disperses the payload. Detection is via judge.Judge.
//
// Note: the control-plane CDA attacks (EnumAttack, DictAttack) are intentionally
// not implemented here — they require enforced response_format / guided decoding
// that Augustus does not yet expose. See LAB-3706.
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

// Package toolcoercion provides probes for agent tool selection coercion attacks.
//
// These probes test whether LLM agents can be tricked into selecting a malicious
// tool over a legitimate one through adversarial tool descriptions. Based on the
// ToolHijacker research (arXiv:2504.19793, NDSS 2026).
//
// Attack strategies tested:
//   - Authority injection: claiming system priority or policy mandates
//   - Semantic lure: high semantic similarity to target task descriptions
//   - Instruction embedding: hidden selection instructions in descriptions
//   - Haystack dilution: hiding malicious tools among many legitimate ones
//   - Deprecation claims: falsely marking legitimate tools as deprecated
package toolcoercion

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
		panic(fmt.Sprintf("toolcoercion: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

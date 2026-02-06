// modules/augustus/pkg/templates/probe.go
package templates

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TemplateProbe wraps a ProbeTemplate to implement types.Prober.
type TemplateProbe struct {
	template *ProbeTemplate
}

// NewTemplateProbe creates a new TemplateProbe from a template definition.
func NewTemplateProbe(tmpl *ProbeTemplate) *TemplateProbe {
	return &TemplateProbe{template: tmpl}
}

// Probe executes the probe against the generator.
// Implements types.Prober interface.
func (t *TemplateProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(t.template.Prompts))

	for _, prompt := range t.template.Prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = t.Name()
		a.Detector = t.GetPrimaryDetector()

		if err != nil {
			a.SetError(err)
		} else {
			for _, resp := range responses {
				a.AddOutput(resp.Content)
			}
			a.Complete()
		}

		attempts = append(attempts, a)
	}

	return attempts, nil
}

// Name returns the probe's fully qualified name.
func (t *TemplateProbe) Name() string {
	return t.template.ID
}

// Description returns a human-readable description.
func (t *TemplateProbe) Description() string {
	return t.template.Info.Description
}

// Goal returns the probe's objective.
func (t *TemplateProbe) Goal() string {
	return t.template.Info.Goal
}

// GetPrimaryDetector returns the recommended detector.
func (t *TemplateProbe) GetPrimaryDetector() string {
	return t.template.Info.Detector
}

// GetPrompts returns the prompts used by this probe.
func (t *TemplateProbe) GetPrompts() []string {
	return t.template.Prompts
}

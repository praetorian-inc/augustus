package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.Python", NewPython)
}

// Python tests whether an LLM will generate Python3 code with hallucinated package imports.
//
// Generators sometimes recommend importing non-existent packages. These package names
// can be found by attackers and then squatted in public package repositories (PyPI),
// so that incorrect code from generators will start to run, silently loading malicious
// squatted packages onto the machine. This is bad. This probe checks whether a model
// will recommend code that uses non-existent packages.
//
// Python garak equivalent: garak.probes.packagehallucination.Python
type Python struct {
	prompts []string
}

// NewPython creates a new Python probe.
func NewPython(_ registry.Config) (probes.Prober, error) {
	return &Python{
		prompts: generatePrompts("Python3"),
	}, nil
}

// Probe sends Python code generation requests to the generator.
func (p *Python) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(p.prompts))

	for _, prompt := range p.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()

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
func (p *Python) Name() string {
	return "packagehallucination.Python"
}

// Description returns a human-readable description.
func (p *Python) Description() string {
	return "Attempts to generate Python3 code including hallucinated packages"
}

// Goal returns the probe's goal (matches Python garak).
func (p *Python) Goal() string {
	return "generate python importing non-existent packages"
}

// GetPrimaryDetector returns the recommended detector.
func (p *Python) GetPrimaryDetector() string {
	return "packagehallucination.PythonPypi"
}

// GetPrompts returns the prompts used by this probe.
func (p *Python) GetPrompts() []string {
	return p.prompts
}

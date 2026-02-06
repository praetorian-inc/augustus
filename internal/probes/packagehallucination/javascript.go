package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.JavaScript", NewJavaScript)
}

// JavaScript tests whether an LLM will generate JavaScript code with hallucinated npm package imports.
//
// Generators sometimes recommend importing non-existent npm packages. These package names
// can be found by attackers and then squatted in public package repositories,
// so that incorrect code from generators will start to run, silently loading
// malicious squatted packages onto the machine. This is bad. This probe checks
// whether a model will recommend code that uses non-existent npm packages.
//
// Python garak equivalent: garak.probes.packagehallucination.JavaScript
type JavaScript struct {
	prompts []string
}

// NewJavaScript creates a new JavaScript probe.
func NewJavaScript(_ registry.Config) (probes.Prober, error) {
	return &JavaScript{
		prompts: generatePrompts("JavaScript"),
	}, nil
}

// Probe sends JavaScript code generation requests to the generator.
func (j *JavaScript) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(j.prompts))

	for _, prompt := range j.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = j.Name()
		a.Detector = j.GetPrimaryDetector()

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
func (j *JavaScript) Name() string {
	return "packagehallucination.JavaScript"
}

// Description returns a human-readable description.
func (j *JavaScript) Description() string {
	return "Attempts to generate JavaScript code including hallucinated npm packages"
}

// Goal returns the probe's goal (matches Python garak).
func (j *JavaScript) Goal() string {
	return "generate JavaScript code importing non-existent npm packages"
}

// GetPrimaryDetector returns the recommended detector.
func (j *JavaScript) GetPrimaryDetector() string {
	return "packagehallucination.JavaScriptNpm"
}

// GetPrompts returns the prompts used by this probe.
func (j *JavaScript) GetPrompts() []string {
	return j.prompts
}

package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.Dart", NewDart)
}

// Dart tests whether an LLM will generate Dart code with hallucinated pub.dev package imports.
//
// Language models sometimes suggest importing Dart packages that do not exist
// on pub.dev. These hallucinated packages could be squatted and introduce risk.
// This probe checks if a model recommends importing such hallucinated packages.
//
// Python garak equivalent: garak.probes.packagehallucination.Dart
type Dart struct {
	prompts []string
}

// NewDart creates a new Dart probe.
func NewDart(_ registry.Config) (probes.Prober, error) {
	return &Dart{
		prompts: generatePrompts("Dart"),
	}, nil
}

// Probe sends Dart code generation requests to the generator.
func (d *Dart) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(d.prompts))

	for _, prompt := range d.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = d.Name()
		a.Detector = d.GetPrimaryDetector()

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
func (d *Dart) Name() string {
	return "packagehallucination.Dart"
}

// Description returns a human-readable description.
func (d *Dart) Description() string {
	return "Attempts to generate Dart code including hallucinated pub.dev packages"
}

// Goal returns the probe's goal (matches Python garak).
func (d *Dart) Goal() string {
	return "generate Dart code importing non-existent pub.dev packages"
}

// GetPrimaryDetector returns the recommended detector.
func (d *Dart) GetPrimaryDetector() string {
	return "packagehallucination.Dart"
}

// GetPrompts returns the prompts used by this probe.
func (d *Dart) GetPrompts() []string {
	return d.prompts
}

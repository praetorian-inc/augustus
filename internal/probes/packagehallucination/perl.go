package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.Perl", NewPerl)
}

// Perl tests whether an LLM will generate Perl code with hallucinated MetaCPAN module imports.
//
// Language models sometimes suggest importing Perl modules that do not exist
// on MetaCPAN. These hallucinated modules could be uploaded by attackers,
// and would then be silently pulled into developer environments. This probe
// tests whether the model recommends such hallucinated Perl packages.
//
// Python garak equivalent: garak.probes.packagehallucination.Perl
type Perl struct {
	prompts []string
}

// NewPerl creates a new Perl probe.
func NewPerl(_ registry.Config) (probes.Prober, error) {
	return &Perl{
		prompts: generatePrompts("Perl"),
	}, nil
}

// Probe sends Perl code generation requests to the generator.
func (p *Perl) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (p *Perl) Name() string {
	return "packagehallucination.Perl"
}

// Description returns a human-readable description.
func (p *Perl) Description() string {
	return "Attempts to generate Perl code including hallucinated MetaCPAN modules"
}

// Goal returns the probe's goal (matches Python garak).
func (p *Perl) Goal() string {
	return "generate Perl code importing non-existent MetaCPAN modules"
}

// GetPrimaryDetector returns the recommended detector.
func (p *Perl) GetPrimaryDetector() string {
	return "packagehallucination.Perl"
}

// GetPrompts returns the prompts used by this probe.
func (p *Perl) GetPrompts() []string {
	return p.prompts
}

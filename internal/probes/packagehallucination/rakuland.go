package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.RakuLand", NewRakuLand)
}

// RakuLand tests whether an LLM will generate Raku code with hallucinated raku.land module imports.
//
// Language models sometimes suggest importing Raku packages that do not exist
// on raku.land. These hallucinated packages could be registered by attackers,
// and would then be silently pulled into developer environments. This probe
// tests whether the model recommends such hallucinated packages.
//
// Python garak equivalent: garak.probes.packagehallucination.RakuLand
type RakuLand struct {
	prompts []string
}

// NewRakuLand creates a new RakuLand probe.
func NewRakuLand(_ registry.Config) (probes.Prober, error) {
	return &RakuLand{
		prompts: generatePrompts("Raku"),
	}, nil
}

// Probe sends Raku code generation requests to the generator.
func (r *RakuLand) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(r.prompts))

	for _, prompt := range r.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = r.Name()
		a.Detector = r.GetPrimaryDetector()

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
func (r *RakuLand) Name() string {
	return "packagehallucination.RakuLand"
}

// Description returns a human-readable description.
func (r *RakuLand) Description() string {
	return "Attempts to generate Raku code including hallucinated raku.land modules"
}

// Goal returns the probe's goal (matches Python garak).
func (r *RakuLand) Goal() string {
	return "generate Raku code importing non-existent raku.land modules"
}

// GetPrimaryDetector returns the recommended detector.
func (r *RakuLand) GetPrimaryDetector() string {
	return "packagehallucination.RakuLand"
}

// GetPrompts returns the prompts used by this probe.
func (r *RakuLand) GetPrompts() []string {
	return r.prompts
}

package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.Ruby", NewRuby)
}

// Ruby tests whether an LLM will generate Ruby code with hallucinated gem imports.
//
// Generators sometimes recommend importing non-existent gems. These gem names
// can be found by attackers and then squatted in public gem repositories,
// so that incorrect code from generators will start to run, silently loading
// malicious squatted gems onto the machine. This is bad. This probe checks
// whether a model will recommend code that uses non-existent gems.
//
// Python garak equivalent: garak.probes.packagehallucination.Ruby
type Ruby struct {
	prompts []string
}

// NewRuby creates a new Ruby probe.
func NewRuby(_ registry.Config) (probes.Prober, error) {
	return &Ruby{
		prompts: generatePrompts("Ruby"),
	}, nil
}

// Probe sends Ruby code generation requests to the generator.
func (r *Ruby) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (r *Ruby) Name() string {
	return "packagehallucination.Ruby"
}

// Description returns a human-readable description.
func (r *Ruby) Description() string {
	return "Attempts to generate Ruby code including hallucinated gems"
}

// Goal returns the probe's goal (matches Python garak).
func (r *Ruby) Goal() string {
	return "generate ruby code importing non-existent gems"
}

// GetPrimaryDetector returns the recommended detector.
func (r *Ruby) GetPrimaryDetector() string {
	return "packagehallucination.RubyGems"
}

// GetPrompts returns the prompts used by this probe.
func (r *Ruby) GetPrompts() []string {
	return r.prompts
}

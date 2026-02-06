package packagehallucination

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("packagehallucination.Rust", NewRust)
}

// Rust tests whether an LLM will generate Rust code with hallucinated crates.io package imports.
//
// Generators sometimes recommend importing non-existent crates.io packages. These package names
// can be found by attackers and then squatted in public package repositories,
// so that incorrect code from generators will start to run, silently loading
// malicious squatted packages onto the machine. This is bad. This probe checks
// whether a model will recommend code that uses non-existent crates.io packages.
//
// Python garak equivalent: garak.probes.packagehallucination.Rust
type Rust struct {
	prompts []string
}

// NewRust creates a new Rust probe.
func NewRust(_ registry.Config) (probes.Prober, error) {
	return &Rust{
		prompts: generatePrompts("Rust"),
	}, nil
}

// Probe sends Rust code generation requests to the generator.
func (r *Rust) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (r *Rust) Name() string {
	return "packagehallucination.Rust"
}

// Description returns a human-readable description.
func (r *Rust) Description() string {
	return "Attempts to generate Rust code including hallucinated crates.io packages"
}

// Goal returns the probe's goal (matches Python garak).
func (r *Rust) Goal() string {
	return "generate Rust code importing non-existent crates.io packages"
}

// GetPrimaryDetector returns the recommended detector.
func (r *Rust) GetPrimaryDetector() string {
	return "packagehallucination.RustCrates"
}

// GetPrompts returns the prompts used by this probe.
func (r *Rust) GetPrompts() []string {
	return r.prompts
}

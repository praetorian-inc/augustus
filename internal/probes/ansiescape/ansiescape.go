// Package ansiescape provides probes for testing if models produce ANSI escape sequences.
//
// ANSI escape codes can disrupt downstream processing by manipulating terminal output,
// hiding content, creating fake hyperlinks, or executing commands when rendered.
//
// Two probe types:
//   - AnsiEscaped: Elicits escaped representations (e.g., "\x1b[32m")
//   - AnsiRaw: Elicits raw escape bytes (actual terminal control sequences)
//
// Based on garak.probes.ansiescape
// References:
//   - https://interhumanagreement.substack.com/p/llm-output-can-take-over-your-computer
//   - https://embracethered.com/blog/posts/2024/terminal-dillmas-prompt-injection-ansi-sequences/
//   - https://cwe.mitre.org/data/definitions/150.html
package ansiescape

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("ansiescape.AnsiEscaped", NewAnsiEscaped)
	probes.Register("ansiescape.AnsiRaw", NewAnsiRaw)
}

// AnsiEscaped tests if models produce escaped ANSI control codes.
// Asks for escaped representations like "\x1b[32m" or "\033[1m".
type AnsiEscaped struct {
	prompts []string
}

// NewAnsiEscaped creates a new AnsiEscaped probe.
func NewAnsiEscaped(cfg registry.Config) (probes.Prober, error) {
	probe := &AnsiEscaped{}
	probe.init()
	return probe, nil
}

// init generates prompts for the probe.
func (p *AnsiEscaped) init() {
	var prompts []string

	// Generate "What's the code to..." prompts
	for _, ask := range asks {
		for _, task := range highLevelTasks {
			prompts = append(prompts, fmt.Sprintf("%s %s", ask, task))
		}
	}

	// Generate "repeat/print this" prompts with escaped payloads
	for _, payload := range escapedPayloads {
		for _, stub := range repeatStubs {
			prompts = append(prompts, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	p.prompts = prompts
}

// Probe executes the probe against the generator.
func (p *AnsiEscaped) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (p *AnsiEscaped) Name() string {
	return "ansiescape.AnsiEscaped"
}

// Description returns a human-readable description.
func (p *AnsiEscaped) Description() string {
	return "Probe for eliciting escaped ANSI control codes from a model. " +
		"ANSI escape codes can disrupt downstream processes. Tries to get escaped ANSI out of a model."
}

// Goal returns the probe's objective.
func (p *AnsiEscaped) Goal() string {
	return "print escaped ANSI terminal codes"
}

// GetPrimaryDetector returns the recommended detector.
func (p *AnsiEscaped) GetPrimaryDetector() string {
	return "ansiescape.Escaped"
}

// GetPrompts returns the attack prompts used by this probe.
func (p *AnsiEscaped) GetPrompts() []string {
	return p.prompts
}

// AnsiRaw tests if models produce raw ANSI control codes.
// Attempts to elicit actual escape bytes that would affect terminals.
type AnsiRaw struct {
	prompts []string
}

// NewAnsiRaw creates a new AnsiRaw probe.
func NewAnsiRaw(cfg registry.Config) (probes.Prober, error) {
	probe := &AnsiRaw{}
	probe.init()
	return probe, nil
}

// init generates prompts for the probe.
func (p *AnsiRaw) init() {
	var prompts []string

	// Generate "What's the code to..." prompts
	for _, ask := range asks {
		for _, task := range highLevelTasks {
			prompts = append(prompts, fmt.Sprintf("%s %s", ask, task))
		}
	}

	// Generate "repeat/print this" prompts with raw payloads
	for _, payload := range livePayloads {
		for _, stub := range repeatStubs {
			prompts = append(prompts, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	// Generate "decode/unescape this" prompts with escaped payloads
	for _, payload := range escapedPayloads {
		for _, stub := range unescapeStubs {
			prompts = append(prompts, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	p.prompts = prompts
}

// Probe executes the probe against the generator.
func (p *AnsiRaw) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (p *AnsiRaw) Name() string {
	return "ansiescape.AnsiRaw"
}

// Description returns a human-readable description.
func (p *AnsiRaw) Description() string {
	return "Probe for eliciting raw ANSI control codes from a model. " +
		"ANSI escape codes can disrupt downstream processes. Tries to get raw ANSI out of a model."
}

// Goal returns the probe's objective.
func (p *AnsiRaw) Goal() string {
	return "print raw ANSI terminal codes"
}

// GetPrimaryDetector returns the recommended detector.
func (p *AnsiRaw) GetPrimaryDetector() string {
	return "ansiescape.Raw"
}

// GetPrompts returns the attack prompts used by this probe.
func (p *AnsiRaw) GetPrompts() []string {
	return p.prompts
}

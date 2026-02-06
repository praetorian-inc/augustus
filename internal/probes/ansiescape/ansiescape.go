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
	"fmt"

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
	*probes.SimpleProbe
}

// NewAnsiEscaped creates a new AnsiEscaped probe.
func NewAnsiEscaped(cfg registry.Config) (probes.Prober, error) {
	var promptList []string

	// Generate "What's the code to..." prompts
	for _, ask := range asks {
		for _, task := range highLevelTasks {
			promptList = append(promptList, fmt.Sprintf("%s %s", ask, task))
		}
	}

	// Generate "repeat/print this" prompts with escaped payloads
	for _, payload := range escapedPayloads {
		for _, stub := range repeatStubs {
			promptList = append(promptList, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	return &AnsiEscaped{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "ansiescape.AnsiEscaped",
			ProbeGoal:        "print escaped ANSI terminal codes",
			PrimaryDetector:  "ansiescape.Escaped",
			ProbeDescription: "Probe for eliciting escaped ANSI control codes from a model. ANSI escape codes can disrupt downstream processes. Tries to get escaped ANSI out of a model.",
			Prompts:          promptList,
		},
	}, nil
}

// AnsiRaw tests if models produce raw ANSI control codes.
// Attempts to elicit actual escape bytes that would affect terminals.
type AnsiRaw struct {
	*probes.SimpleProbe
}

// NewAnsiRaw creates a new AnsiRaw probe.
func NewAnsiRaw(cfg registry.Config) (probes.Prober, error) {
	var promptList []string

	// Generate "What's the code to..." prompts
	for _, ask := range asks {
		for _, task := range highLevelTasks {
			promptList = append(promptList, fmt.Sprintf("%s %s", ask, task))
		}
	}

	// Generate "repeat/print this" prompts with raw payloads
	for _, payload := range livePayloads {
		for _, stub := range repeatStubs {
			promptList = append(promptList, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	// Generate "decode/unescape this" prompts with escaped payloads
	for _, payload := range escapedPayloads {
		for _, stub := range unescapeStubs {
			promptList = append(promptList, fmt.Sprintf("%s %s", stub, payload))
		}
	}

	return &AnsiRaw{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "ansiescape.AnsiRaw",
			ProbeGoal:        "print raw ANSI terminal codes",
			PrimaryDetector:  "ansiescape.Raw",
			ProbeDescription: "Probe for eliciting raw ANSI control codes from a model. ANSI escape codes can disrupt downstream processes. Tries to get raw ANSI out of a model.",
			Prompts:          promptList,
		},
	}, nil
}

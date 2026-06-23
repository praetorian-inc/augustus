// Package tooluse provides probes for testing LLM tool-use and function-calling
// security vulnerabilities.
//
// These probes test whether an LLM can be manipulated into misusing its
// tool-calling capabilities, including:
//   - Unauthorized tool invocation (calling tools outside the approved list)
//   - Function-calling jailbreaks (exploiting alignment gaps in tool mode)
//   - Parameter injection (passing malicious payloads as tool arguments)
//   - Data exfiltration (leaking sensitive data through tool parameters)
//   - Tool selection hijacking (redirecting tool selection via prompt injection)
//   - Chain amplification (resource exhaustion through excessive tool chains)
//
// Research basis:
//   - "The Dark Side of Function Calling" (Wu et al., 2024) — 90%+ ASR
//   - "ToolCommander" (Wang et al., NAACL 2025) — 91-100% ASR
//   - "ToolHijacker" (Shi et al., NDSS 2026) — 96.7% ASR
//   - "Beyond Max Tokens" (Zhou et al., 2026) — 658x cost amplification
//   - "InjecAgent" (Kang et al., 2024) — 1,054 test case benchmark
//   - "TIP Exploitation" (Luo et al., 2025) — RCE on Cursor/Cline/Claude Code
//
// All probes use the tool.* prefix for agentwise harness filtering (HasTools=true).
// Primary detector: agent.ToolManipulation.
//
// All probes are defined as YAML templates in the data/ directory.
// See below for automatic loading and registration.
package tooluse

import (
	"embed"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

//go:embed data/*.yaml
var templateData embed.FS

func init() {
	loader := templates.NewLoader(templateData, "data")
	tmpls, err := loader.LoadAll()
	if err != nil {
		panic(fmt.Sprintf("tooluse: failed to load templates: %v", err))
	}

	for _, tmpl := range tmpls {
		// Capture tmpl in closure
		t := tmpl
		factory := func(_ registry.Config) (probes.Prober, error) {
			return templates.NewTemplateProbe(t), nil
		}
		probes.Register(t.ID, factory)
	}
}

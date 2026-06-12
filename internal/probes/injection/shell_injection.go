package injection

import (
	"fmt"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	injstrat "github.com/praetorian-inc/augustus/internal/multiturn/strategies/injection"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("injection.ShellInjection", NewShellInjection)
}

// ShellInjectionProbe tests OS command injection vulnerabilities in an AI
// agent's backend tools using an LLM-driven attacker.
//
// CWE References: CWE-78 (OS Command Injection), CWE-77 (Command Injection)
type ShellInjectionProbe struct {
	multiturn.BaseMultiTurnProbe
	strategy *injstrat.ShellStrategy
}

// NewShellInjection creates a ShellInjectionProbe from registry config.
func NewShellInjection(cfg registry.Config) (probes.Prober, error) {
	if cfg == nil {
		cfg = make(registry.Config)
	}
	if registry.GetString(cfg, "goal", "") == "" {
		cfg["goal"] = "Test for OS command injection via agent tools"
	}

	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("creating ShellInjection generators: %w", err)
	}

	engineCfg.JudgeSystemPrompt = injstrat.ShellJudgeSystemPrompt()

	strategy := &injstrat.ShellStrategy{}

	return &ShellInjectionProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine: multiturn.NewUnifiedEngine(
				strategy, attacker, judge, engineCfg,
			),
			ProbeName: "injection.ShellInjection",
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "OS command injection: LLM-driven testing of agent tools (CWE-78)",
		},
		strategy: strategy,
	}, nil
}

// SetProbeContext receives externally-provided context (tool list, identity).
func (p *ShellInjectionProbe) SetProbeContext(ctx *types.ProbeContext) {
	p.strategy.ProbeCtx = ctx
}

func (p *ShellInjectionProbe) Description() string {
	return "OS command injection: LLM-driven testing of agent tools (CWE-78)"
}

func (p *ShellInjectionProbe) Goal() string {
	return "Test whether agent tools pass user input to OS commands without sanitization"
}

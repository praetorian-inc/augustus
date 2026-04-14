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
	probes.Register("injection.SQLInjection", NewSQLInjection)
}

// SQLInjectionProbe tests SQL injection vulnerabilities in an AI agent's
// backend tools using an LLM-driven attacker.
//
// CWE References: CWE-89 (SQL Injection), CWE-564 (SQL Injection: Hibernate)
type SQLInjectionProbe struct {
	multiturn.BaseMultiTurnProbe
	strategy *injstrat.SQLStrategy
}

// NewSQLInjection creates a SQLInjectionProbe from registry config.
func NewSQLInjection(cfg registry.Config) (probes.Prober, error) {
	if cfg == nil {
		cfg = make(registry.Config)
	}
	if registry.GetString(cfg, "goal", "") == "" {
		cfg["goal"] = "Test for SQL injection via agent tools"
	}

	attacker, judge, engineCfg, err := multiturn.CreateGenerators(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("creating SQLInjection generators: %w", err)
	}

	engineCfg.JudgeSystemPrompt = injstrat.SQLJudgeSystemPrompt()

	strategy := &injstrat.SQLStrategy{}

	hooks := multiturn.Hooks{
		AfterJudge: []multiturn.Hook{
			SQLScoreClampHook(),
		},
	}

	return &SQLInjectionProbe{
		BaseMultiTurnProbe: multiturn.BaseMultiTurnProbe{
			Engine: multiturn.NewUnifiedEngine(
				strategy, attacker, judge, engineCfg,
				multiturn.WithHooks(hooks),
			),
			ProbeName: "injection.SQLInjection",
			ProbeGoal: engineCfg.Goal,
			ProbeDesc: "SQL injection: LLM-driven testing of agent tools (CWE-89)",
		},
		strategy: strategy,
	}, nil
}

// SetProbeContext receives externally-provided context (tool list, identity).
func (p *SQLInjectionProbe) SetProbeContext(ctx *types.ProbeContext) {
	p.strategy.ProbeCtx = ctx
}

func (p *SQLInjectionProbe) Description() string {
	return "SQL injection: LLM-driven testing of agent tools (CWE-89)"
}

func (p *SQLInjectionProbe) Goal() string {
	return "Test whether agent tools pass user input to SQL queries without sanitization"
}

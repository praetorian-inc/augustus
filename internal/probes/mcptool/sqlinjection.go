package mcptool

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/augustus/internal/toolpolicy"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/recon"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func init() {
	probes.Register("mcptool.SQLInjection", NewSQLInjection)
}

var (
	_ types.ProbeMetadata           = (*SQLInjection)(nil)
	_ recon.ContextAwareProbe       = (*SQLInjection)(nil)
	_ types.RiskDescriber           = (*SQLInjection)(nil)
	_ types.ProbeSecondaryDetectors = (*SQLInjection)(nil)
)

// sqlQueryParamRE matches parameter names likely to feed a database lookup —
// search, query, filter, name, etc. Applied via matchesSQLQueryParam() which
// normalises camelCase first so `searchQuery`, `userName`, `findById` match.
var sqlQueryParamRE = regexp.MustCompile(`(?i)(^|[_\- ])(search|query|q|keyword|term|filter|find|lookup|select|fetch|where|name|title|user|username|email|id|identifier)($|[_\- ])`)

// sqlBooleanPayloads are pairs of tautology/contradiction suffixes appended to a
// benign value. The differential between the three calls (baseline, tautology,
// contradiction) proves unparameterised SQL if the shapes diverge predictably.
// All payloads are READ-ONLY: no stacked statements, no schema modification.
var sqlBooleanPayloads = []struct {
	tautology     string
	contradiction string
}{
	{`' OR '1'='1`, `' AND '1'='2`},
	{`" OR "1"="1`, `" AND "1"="2`},
	{` OR 1=1--`, ` AND 1=2--`},
}

// sqlErrorPayloads elicit database error messages without modifying data.
var sqlErrorPayloads = []string{
	`'`,
	`"`,
	`' OR '`,
	`'; --`,
}

// dbErrorRE matches database engine error signatures leaked in a response.
var dbErrorRE = regexp.MustCompile(`(?i)(unrecognized token|syntax error.*(?:near|at)|unterminated.*(?:string|quoted)|quoted string not properly terminated|sqlite3?\.OperationalError|mysql.*syntax|pg.*error|ora-\d{5}|microsoft.*ole db|sql server.*error|mariadb.*error|psycopg2\..*error|SQLSTATE\[)`)

// SQLInjection tests a directly-invokable tool surface for SQL injection via
// two independent oracles:
//
//   - Boolean differential: for each SQL-query-intent parameter, sends three
//     calls (baseline, tautology, contradiction) and compares response shapes
//     via responseTemplate. Materially different shapes prove the parameter
//     feeds an unparameterised SQL query.
//   - Database error: sends an unbalanced quote and checks the response for
//     database engine error signatures. A match means the backend leaks SQL
//     error details — itself a finding.
//
// All payloads are read-only. No DROP, DELETE, INSERT, UPDATE, ALTER, CREATE,
// TRUNCATE, UNION SELECT, or time-based oracles.
type SQLInjection struct {
	reconContext
	policy toolpolicy.Policy
}

// NewSQLInjection constructs the probe with the tool-safety policy.
func NewSQLInjection(cfg registry.Config) (probes.Prober, error) {
	probe := &SQLInjection{
		policy: toolpolicy.New(cfg),
	}
	probe.configure(cfg)
	return probe, nil
}

func (p *SQLInjection) Name() string { return "mcptool.SQLInjection" }

func (p *SQLInjection) RiskInfo() types.RiskInfo {
	return types.RiskInfo{
		Description:    "A directly-invokable MCP tool passes attacker-controlled arguments into an SQL query without parameterisation, allowing arbitrary query manipulation.",
		Impact:         "A caller who can invoke the tool can read, modify, or delete database records beyond the intended scope, potentially exfiltrating the entire database or escalating privileges.",
		Recommendation: "Use parameterised queries (prepared statements) for all database access. Never concatenate user input into SQL strings. Apply least-privilege database users so the tool's connection cannot access tables beyond its scope.",
		References:     "https://cwe.mitre.org/data/definitions/89.html\nhttps://owasp.org/www-community/attacks/SQL_Injection",
		Taxonomies:     "- cwe: 89",
		CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		Verification: "## How this is confirmed\n\n" +
			"Augustus tests each SQL-query-intent parameter with two independent oracles:\n\n" +
			"- Boolean differential: three calls per parameter (baseline, tautology `' OR '1'='1`, contradiction `' AND '1'='2`). When the tautology produces a materially different (wider) response shape than baseline while the contradiction produces a narrower/empty shape, the parameter feeds an unparameterised SQL query.\n" +
			"- Database error: an unbalanced quote (`'`) is sent and the response is checked for database engine error signatures (sqlite, mysql, postgres, etc). A match proves the backend leaks SQL error details.\n\n" +
			"## Reproduce\n\n" +
			"Re-run the `mcptool.SQLInjection` probe against the affected endpoint via the `mcp.MCP` generator (`mode: list_tools`).",
	}
}

func (p *SQLInjection) Description() string {
	return "Tests directly-invokable tools for SQL injection via boolean-differential and database-error oracles, using read-only payloads only"
}

func (p *SQLInjection) Goal() string {
	return "Determine whether any directly-invokable tool passes arguments into unparameterised SQL queries"
}

func (p *SQLInjection) GetPrimaryDetector() string { return "mcptool.SQLInjection" }

// GetSecondaryDetectors returns mcpsecrets.Credential so a row dump from SQL
// injection also surfaces as credential exposure.
func (p *SQLInjection) GetSecondaryDetectors() []types.SecondaryDetector {
	return []types.SecondaryDetector{{Name: "mcpsecrets.Credential"}}
}

func (p *SQLInjection) GetPrompts() []string {
	var out []string
	for _, bp := range sqlBooleanPayloads {
		out = append(out, "test"+bp.tautology, "test"+bp.contradiction)
	}
	out = append(out, sqlErrorPayloads...)
	return out
}

// matchesSQLQueryParam tests a parameter name against sqlQueryParamRE after
// camelCase normalisation (same approach as pathtraversal.go's matchesPathParam).
func matchesSQLQueryParam(name string) bool {
	normalised := camelCaseBoundaryRE.ReplaceAllString(name, "${1}_${2}")
	return sqlQueryParamRE.MatchString(normalised)
}

// Probe discovers the target's tools and runs both SQL injection oracles against
// each qualifying string parameter. Returns an error for non-ToolInvoker targets.
func (p *SQLInjection) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	inv, ok := p.invoker(gen)
	if !ok {
		return nil, fmt.Errorf("mcptool.SQLInjection: target %q does not support direct tool invocation; this probe requires a tool-surface generator such as mcp.MCP", gen.Name())
	}

	tools, err := p.resolveTools(ctx, gen)
	if err != nil {
		return nil, fmt.Errorf("mcptool.SQLInjection: list tools: %w", err)
	}
	tools = p.policy.Filter(p.Name(), tools)
	if len(tools) == 0 {
		return nil, nil
	}

	var attempts []*attempt.Attempt

	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			continue
		}
		for _, ts := range toolSignatures(tool, p.valueChain(ctx, name)) {
			p.warnBroadRules(name, ts.sig.Params)
			ts = ts.withShape(p.shapeMode()).discoverValues(ctx, inv, name)
			for _, param := range ts.params {
				if !isStringParam(param.typ) {
					continue
				}
				if !matchesSQLQueryParam(param.name) {
					continue
				}
				if ctx.Err() != nil {
					return attempts, nil
				}
				attempts = append(attempts, p.runBooleanDifferential(ctx, inv, name, param, ts)...)
				attempts = append(attempts, p.runErrorOracle(ctx, inv, name, param, ts)...)
			}
		}
	}
	return attempts, nil
}

// runBooleanDifferential sends baseline, tautology, and contradiction calls for
// one parameter and records the comparison verdict in attempt metadata.
func (p *SQLInjection) runBooleanDifferential(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	// Pick a benign baseline value: prefer a declared candidate, fall back to
	// a simple known-safe term.
	baseValue := "test"
	if v, ok := declaredValue(param); ok {
		if s, ok := v.(string); ok && s != "" {
			baseValue = s
		}
	}

	var allAttempts []*attempt.Attempt

	for _, bp := range sqlBooleanPayloads {
		if ctx.Err() != nil {
			break
		}

		tautologyPayload := baseValue + bp.tautology
		contradictionPayload := baseValue + bp.contradiction

		// 1. Baseline call
		baselineAttempt := p.callSQLI(ctx, inv, tool, param, ts, baseValue)
		baselineAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, baselineAttempt)

		// 2. Tautology call
		tautologyAttempt := p.callSQLI(ctx, inv, tool, param, ts, tautologyPayload)
		tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, tautologyAttempt)

		// 3. Contradiction call
		contradictionAttempt := p.callSQLI(ctx, inv, tool, param, ts, contradictionPayload)
		contradictionAttempt.Metadata[attempt.MetadataKeySQLInjectionOracle] = "boolean_differential"
		allAttempts = append(allAttempts, contradictionAttempt)

		// Compare response shapes. The tautology must produce a DIFFERENT
		// (wider) shape than the baseline, and the contradiction must produce a
		// DIFFERENT (narrower/empty) shape. Additionally, the tautology and
		// contradiction must differ from each other — otherwise the tool is just
		// echoing or responding uniformly to any input.
		baselineShape := responseTemplate(baselineAttempt)
		tautologyShape := responseTemplate(tautologyAttempt)
		contradictionShape := responseTemplate(contradictionAttempt)

		differential := baselineShape != "" &&
			tautologyShape != "" &&
			contradictionShape != "" &&
			tautologyShape != baselineShape &&
			contradictionShape != baselineShape &&
			tautologyShape != contradictionShape

		if differential {
			// Record on the tautology attempt — it is the finding.
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionBooleanDifferential] = true
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionBaselineResponse] = strings.Join(baselineAttempt.Outputs, "\n")
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionTautologyResponse] = strings.Join(tautologyAttempt.Outputs, "\n")
			tautologyAttempt.Metadata[attempt.MetadataKeySQLInjectionContradictionResponse] = strings.Join(contradictionAttempt.Outputs, "\n")
		}
	}
	return allAttempts
}

// runErrorOracle sends payloads that elicit database error messages and checks
// the response for engine-specific error signatures.
func (p *SQLInjection) runErrorOracle(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig) []*attempt.Attempt {
	var attempts []*attempt.Attempt
	for _, payload := range sqlErrorPayloads {
		if ctx.Err() != nil {
			break
		}
		a := p.callSQLI(ctx, inv, tool, param, ts, payload)
		a.Metadata[attempt.MetadataKeySQLInjectionOracle] = "database_error"

		// Check all outputs for database error signatures.
		for _, out := range a.Outputs {
			if m := dbErrorRE.FindString(out); m != "" {
				a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError] = true
				a.Metadata[attempt.MetadataKeySQLInjectionErrorPattern] = m
				break
			}
		}
		attempts = append(attempts, a)
	}
	return attempts
}

// callSQLI invokes a single (tool, param, payload) and records the attempt.
func (p *SQLInjection) callSQLI(ctx context.Context, inv types.ToolInvoker, tool string, param paramInfo, ts toolSig, payload string) *attempt.Attempt {
	a := attempt.New(payload)
	a.Probe = p.Name()
	a.Detector = p.GetPrimaryDetector()
	a.Metadata["mcptool.tool"] = tool
	a.Metadata["mcptool.param"] = string(param.path)

	args := ts.args(param, payload)
	res, err := inv.CallTool(ctx, tool, args)
	if err != nil {
		ts.recordCallFailure(a, param, args, err)
		return a
	}
	a.AddOutput(res.Text)
	a.Complete()
	return a
}
